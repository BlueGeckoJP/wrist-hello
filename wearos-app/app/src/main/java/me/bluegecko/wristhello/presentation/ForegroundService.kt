package me.bluegecko.wristhello.presentation

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.PackageManager
import android.os.IBinder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import me.bluegecko.wristhello.R

class ForegroundService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private lateinit var bleManager: BleManager
    private var reconnectJob: Job? = null
    private var reconnectRequested = false

    private fun requestReconnect() {
        reconnectJob?.cancel()
        reconnectJob = null

        reconnectRequested = true

        if (checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
            stopSelf()
            return
        }

        bleManager.disconnect()
    }

    override fun onCreate() {
        super.onCreate()

        createNotificationChannel()
        createChallengeNotificationChannel()

        startForeground(NOTIFICATION_ID, buildNotification("BLE foreground service is starting..."))

        bleManager = BleManager(
            context = applicationContext,
            keyStoreManager = KeystoreManager(),
            scope = scope,
            onChallengeReceived = { showChallengeNotification() },
            onCancelReceived = { cancelChallengeNotification() }
        )

        scope.launch {
            bleManager.bleState.collect { state ->
                BleServiceState.update(state)

                when (state) {
                    BleState.Connecting -> {
                        updateNotification("BLE connecting...")
                    }

                    BleState.Connected -> {
                        reconnectJob?.cancel()
                        reconnectJob = null
                        updateNotification("BLE connected")
                    }

                    BleState.Disconnected -> {
                        updateNotification("BLE reconnecting...")

                        if (reconnectRequested) {
                            reconnectRequested = false
                            connectIfPossible()
                        } else {
                            scheduleReconnect()
                        }
                    }

                    is BleState.Error -> {
                        updateNotification("BLE error: ${state.message}")
                        scheduleReconnect()
                    }
                }
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_RECONNECT -> {
                requestReconnect()
            }

            ACTION_APPROVE_CHALLENGE -> {
                bleManager.approvePendingChallenge()
                cancelChallengeNotification()
            }

            ACTION_DENY_CHALLENGE -> {
                bleManager.denyPendingChallenge()
                cancelChallengeNotification()
            }

            else -> connectIfPossible()
        }

        return START_STICKY
    }

    override fun onDestroy() {
        reconnectJob?.cancel()

        if (checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED) {
            bleManager.disconnect()
        }

        scope.cancel()
        super.onDestroy()
    }

    override fun onBind(p0: Intent?): IBinder? = null

    private fun connectIfPossible() {
        if (checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
            stopSelf()
            return
        }

        bleManager.connectToPairedDevice()
    }

    private fun scheduleReconnect() {
        if (reconnectJob?.isActive == true) return

        reconnectJob = scope.launch {
            delay(5000)
            connectIfPossible()
        }
    }

    private fun createNotificationChannel() {
        val manager = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            CHANNEL_ID,
            "BLE connection",
            NotificationManager.IMPORTANCE_LOW
        )
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(text: String): Notification {
        return Notification.Builder(this, CHANNEL_ID).setContentTitle("Wrist Hello")
            .setContentText(text).setSmallIcon(R.mipmap.ic_launcher).setOngoing(true).build()
    }

    private fun updateNotification(text: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun createChallengeNotificationChannel() {
        val manager = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            CHALLENGE_CHANNEL_ID,
            "Challenge alerts",
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = "Alerts when a challenge is received"
            enableVibration(true)
            vibrationPattern = longArrayOf(0, 300, 200, 300)
            setSound(null, null)
        }
        manager.createNotificationChannel(channel)
    }

    private fun showChallengeNotification() {
        val manager = getSystemService(NotificationManager::class.java)

        val approveIntent =
            Intent(this, ForegroundService::class.java).setAction(ACTION_APPROVE_CHALLENGE)
        val approvePendingIntent = PendingIntent.getForegroundService(
            this,
            REQUEST_APPROVE_CHALLENGE,
            approveIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val denyIntent =
            Intent(this, ForegroundService::class.java).setAction(ACTION_DENY_CHALLENGE)
        val denyPendingIntent = PendingIntent.getForegroundService(
            this,
            REQUEST_DENY_CHALLENGE,
            denyIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification =
            Notification.Builder(this, CHALLENGE_CHANNEL_ID)
                .setContentTitle("Wrist Hello")
                .setContentText("Approve sign-in?")
                .setStyle(
                    Notification.BigTextStyle().bigText(
                        """
                            A sign-in challenge was received.
                            Approve to sign and reply.
                        """.trimIndent()
                    )
                ).setSmallIcon(R.mipmap.ic_launcher)
                .setAutoCancel(true)
                .addAction(
                    Notification.Action.Builder(
                        R.mipmap.ic_launcher,
                        "Approve",
                        approvePendingIntent
                    ).build()
                )
                .addAction(
                    Notification.Action.Builder(
                        R.mipmap.ic_launcher,
                        "Deny",
                        denyPendingIntent
                    ).build()
                )
                .build()

        manager.notify(CHALLENGE_NOTIFICATION_ID, notification)
    }

    private fun cancelChallengeNotification() {
        val manager = getSystemService(NotificationManager::class.java)
        manager.cancel(CHALLENGE_NOTIFICATION_ID)
    }

    companion object {
        private const val CHANNEL_ID = "ble_foreground"
        private const val CHALLENGE_CHANNEL_ID = "challenge_alerts"
        private const val NOTIFICATION_ID = 1001
        private const val CHALLENGE_NOTIFICATION_ID = 1002
        private const val REQUEST_APPROVE_CHALLENGE = 2001
        private const val REQUEST_DENY_CHALLENGE = 2002
        const val ACTION_RECONNECT = "me.bluegecko.wristhello.action.RECONNECT"
        const val ACTION_APPROVE_CHALLENGE = "me.bluegecko.wristhello.action.APPROVE_CHALLENGE"
        const val ACTION_DENY_CHALLENGE = "me.bluegecko.wristhello.action.DENY_CHALLENGE"
    }
}
