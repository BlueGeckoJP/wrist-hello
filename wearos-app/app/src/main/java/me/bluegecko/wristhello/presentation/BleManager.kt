package me.bluegecko.wristhello.presentation

import android.Manifest
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.content.Context
import android.os.ParcelUuid
import android.util.Log
import androidx.annotation.RequiresPermission
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.util.UUID
import kotlin.time.Duration.Companion.milliseconds

private val SERVICE_UUID = UUID.fromString("ddc6ea97-db6e-4ecd-a3ff-0143368ef829")
private val CHALLENGE_CHAR_UUID = UUID.fromString("5794ca86-3a5e-45ca-85f9-42a74cd460a7")
private val RESPONSE_CHAR_UUID = UUID.fromString("f68c58c2-a1f2-456f-a118-f1c6ce566a0a")
private val CANCEL_CHAR_UUID = UUID.fromString("2679d328-1fb9-4cd5-9efe-382a723bcad7")

private val CCCD_UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

private val DENY_RESPONSE = byteArrayOf(0x00)
private const val APPROVE_TIMEOUT_MILLIS = 30_000L

sealed class BleState {
    object Disconnected : BleState()
    object Connecting : BleState()
    object Connected : BleState()
    data class Error(val message: String) : BleState()
}

private sealed class ApprovalResult {
    data object Approved : ApprovalResult()
    data object Denied : ApprovalResult()
    data object Cancelled : ApprovalResult()
}

private class PendingApproval(
    val challenge: ByteArray,
    val result: CompletableDeferred<ApprovalResult>
)

class BleManager(
    private val context: Context,
    private val keyStoreManager: KeystoreManager,
    private val scope: CoroutineScope,
    private val onChallengeReceived: (() -> Unit)? = null,
    private val onCancelReceived: (() -> Unit)? = null,
) {
    private var gatt: BluetoothGatt? = null
    private val notifyEnableQueue = ArrayDeque<BluetoothGattCharacteristic>()

    private val _bleState = MutableStateFlow<BleState>(BleState.Disconnected)
    val bleState: StateFlow<BleState> = _bleState

    private var pendingApproval: PendingApproval? = null

    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    fun findDeviceByServiceUuid(context: Context, targetUuid: UUID): BluetoothDevice? {
        val adapter =
            (context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager).adapter
        if (adapter == null || !adapter.isEnabled) return null

        val targetParcelUuid = ParcelUuid.fromString(targetUuid.toString())
        return adapter.bondedDevices?.firstOrNull { device ->
            device.uuids?.contains(targetParcelUuid) == true
        }
    }

    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    fun connectToPairedDevice() {
        if (_bleState.value is BleState.Connecting || _bleState.value is BleState.Connected) {
            return
        }

        val target: BluetoothDevice? = findDeviceByServiceUuid(context, SERVICE_UUID)
        if (target == null) {
            _bleState.value = BleState.Error("No paired device found")
            return
        }

        _bleState.value = BleState.Connecting
        gatt = target.connectGatt(context, false, gattCallback, BluetoothDevice.TRANSPORT_LE)
    }

    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    fun disconnect() {
        val currentGatt = gatt
        if (currentGatt == null) {
            _bleState.value = BleState.Disconnected
            return
        }
        currentGatt.disconnect()
    }

    fun approvePendingChallenge() {
        pendingApproval?.result?.complete(ApprovalResult.Approved)
    }

    fun denyPendingChallenge() {
        pendingApproval?.result?.complete(ApprovalResult.Denied)
    }

    private val gattCallback = object : BluetoothGattCallback() {
        @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            when (newState) {
                BluetoothProfile.STATE_CONNECTED -> {
                    this@BleManager.gatt = gatt
                    gatt.requestMtu(512)

                    gatt.discoverServices()
                }

                BluetoothProfile.STATE_DISCONNECTED -> {
                    notifyEnableQueue.clear()
                    _bleState.value = BleState.Disconnected
                    gatt.close()
                    this@BleManager.gatt = null
                }
            }
        }

        @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            Log.d("BleManager", "onMtuChanged: mtu=$mtu, status=$status")
        }

        @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                _bleState.value = BleState.Error("Failed to discover services: status=$status")
                return
            }

            val service = gatt.getService(SERVICE_UUID)
            val challengeChar =
                service?.getCharacteristic(CHALLENGE_CHAR_UUID)
            val cancelChar =
                service?.getCharacteristic(CANCEL_CHAR_UUID)

            if (challengeChar == null || cancelChar == null) {
                _bleState.value = BleState.Error("CHALLENGE_CHAR or CANCEL_CHAR not found")
                return
            }

            enableNotify(gatt, listOf(challengeChar, cancelChar))
        }

        @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
        override fun onDescriptorWrite(
            gatt: BluetoothGatt,
            descriptor: BluetoothGattDescriptor,
            status: Int
        ) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                notifyEnableQueue.clear()
                _bleState.value = BleState.Error("Failed to enable notify: status=$status")
                return
            }

            enableNextNotify(gatt)
        }

        @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray
        ) {
            when (characteristic.uuid) {
                CHALLENGE_CHAR_UUID -> scope.launch { handleChallenge(gatt, value) }
                CANCEL_CHAR_UUID -> {
                    Log.d("BleManager", "Received cancel notification")
                    val pending = pendingApproval
                    if (pending != null && pending.challenge.contentEquals(value)) {
                        Log.i("BleManager", "Challenge canceled by device")
                        pending.result.complete(ApprovalResult.Cancelled)
                        onCancelReceived?.invoke()
                    }
                }
            }
        }
    }

    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    private fun enableNotify(
        gatt: BluetoothGatt,
        characteristics: List<BluetoothGattCharacteristic>
    ) {
        notifyEnableQueue.clear()
        notifyEnableQueue.addAll(characteristics)
        enableNextNotify(gatt)
    }

    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    private fun enableNextNotify(gatt: BluetoothGatt) {
        if (notifyEnableQueue.isEmpty()) {
            _bleState.value = BleState.Connected
            return
        }

        val characteristic = notifyEnableQueue.removeFirst()
        gatt.setCharacteristicNotification(characteristic, true)

        val descriptor = characteristic.getDescriptor(CCCD_UUID)
        if (descriptor == null) {
            enableNextNotify(gatt)
            return
        }

        val status = gatt.writeDescriptor(
            descriptor,
            BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
        )
        if (status != BluetoothStatusCodes.SUCCESS) {
            notifyEnableQueue.clear()
            _bleState.value = BleState.Error("Failed to enable notify: status=$status")
        }
    }

    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    private suspend fun handleChallenge(gatt: BluetoothGatt, challenge: ByteArray) {

        val approval = CompletableDeferred<ApprovalResult>()
        val pending = PendingApproval(challenge, approval)
        pendingApproval = pending

        onChallengeReceived?.invoke()

        val result = withTimeoutOrNull(APPROVE_TIMEOUT_MILLIS.milliseconds) {
            approval.await()
        } ?: ApprovalResult.Denied

        if (pendingApproval === pending) {
            pendingApproval = null
        }

        when (result) {
            ApprovalResult.Approved -> {
                if (!keyStoreManager.hasKey()) {
                    keyStoreManager.getOrGenerateRawPublicKey()
                }
                val response = keyStoreManager.signChallenge(challenge) ?: return
                writeResponse(gatt, response)
            }

            ApprovalResult.Denied -> {
                writeResponse(gatt, DENY_RESPONSE + challenge)
                return
            }

            ApprovalResult.Cancelled -> return
        }
    }

    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    private fun writeResponse(gatt: BluetoothGatt, response: ByteArray) {
        val responseChar =
            gatt.getService(SERVICE_UUID)?.getCharacteristic(RESPONSE_CHAR_UUID) ?: return

        gatt.writeCharacteristic(
            responseChar,
            response,
            BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
        )
    }
}
