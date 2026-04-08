package me.bluegecko.wristhello.presentation

import android.Manifest
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.content.Context
import android.os.Build
import android.os.ParcelUuid
import androidx.annotation.RequiresPermission
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.util.UUID

private val SERVICE_UUID = UUID.fromString("ddc6ea97-db6e-4ecd-a3ff-0143368ef829")
private val CHALLENGE_CHAR_UUID = UUID.fromString("5794ca86-3a5e-45ca-85f9-42a74cd460a7")
private val RESPONSE_CHAR_UUID = UUID.fromString("f68c58c2-a1f2-456f-a118-f1c6ce566a0a")

private val CCCD_UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

sealed class BleState {
    object Disconnected : BleState()
    object Connecting : BleState()
    object Connected : BleState()
    data class Error(val message: String) : BleState()
}

class BleManager(private val context: Context, private val keyStoreManager: KeystoreManager) {
    private var gatt: BluetoothGatt? = null

    private val _bleState = MutableStateFlow<BleState>(BleState.Disconnected)
    val bleState: StateFlow<BleState> = _bleState

    private val _challengeData = MutableStateFlow<ByteArray?>(null)
    val challengeData: StateFlow<ByteArray?> = _challengeData

    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    fun findDeviceByServiceUuid(context: Context, targetUuid: UUID): BluetoothDevice? {
        val adapter = (context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager).adapter
        if (adapter == null || !adapter.isEnabled) return null

        val targetParcelUuid = ParcelUuid.fromString(targetUuid.toString())
        return adapter.bondedDevices?.firstOrNull { device ->
            device.uuids?.contains(targetParcelUuid) == true
        }
    }

    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    fun connectToPairedDevice() {
        val adapter = (context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager).adapter

        val target: BluetoothDevice? = findDeviceByServiceUuid(context, SERVICE_UUID)
        if (target == null) {
            _bleState.value = BleState.Error("No paired device found")
            return
        }

        _bleState.value = BleState.Connecting
        target.connectGatt(context, false, gattCallback, BluetoothDevice.TRANSPORT_LE)
    }

    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    fun disconnect() {
        gatt?.disconnect()
    }

    private val gattCallback = object : BluetoothGattCallback() {
        @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
           when(newState) {
               BluetoothProfile.STATE_CONNECTED -> {
                   this@BleManager.gatt = gatt
                   gatt.discoverServices()
               }

               BluetoothProfile.STATE_DISCONNECTED -> {
                   _bleState.value = BleState.Disconnected
                   gatt.close()
                   this@BleManager.gatt = null
               }
           }
        }

        @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                _bleState.value = BleState.Error("Failed to discover services: status=$status")
                return
            }

            val challengeChar =
                gatt.getService(SERVICE_UUID)?.getCharacteristic(CHALLENGE_CHAR_UUID)

            if (challengeChar == null) {
                _bleState.value = BleState.Error("CHALLENGE_CHAR not found")
                return
            }

            enableNotify(gatt, challengeChar)

            _bleState.value = BleState.Connected
        }

        @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray
        ) {
            if (characteristic.uuid == CHALLENGE_CHAR_UUID) {
                handleChallenge(gatt, value)
            }
        }
    }

    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    private fun enableNotify(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic) {
        gatt.setCharacteristicNotification(characteristic, true)

        val descriptor = characteristic.getDescriptor(CCCD_UUID) ?: return
        gatt.writeDescriptor(descriptor, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
    }

    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    private fun handleChallenge(gatt: BluetoothGatt, challenge: ByteArray) {
        _challengeData.value = challenge

        if (!keyStoreManager.hasKey()) {
            keyStoreManager.getOrGenerateRawPublicKey()
        }
        val response = keyStoreManager.signChallenge(challenge) ?: return

        writeResponse(gatt, response)
    }

    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    private fun writeResponse(gatt: BluetoothGatt, response: ByteArray) {
        val responseChar = gatt.getService(SERVICE_UUID)?.getCharacteristic(RESPONSE_CHAR_UUID) ?: return

        gatt.writeCharacteristic(responseChar, response, BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT)
    }
}