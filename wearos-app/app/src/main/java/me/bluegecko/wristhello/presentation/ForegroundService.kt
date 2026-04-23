package me.bluegecko.wristhello.presentation

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
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

    override fun onCreate() {
        super.onCreate()

        createNotificationChannel()
        createChallengeNotificationChannel()

        startForeground(NOTIFICATION_ID, buildNotification("BLE foreground service is starting..."))

        bleManager = BleManager(
            context = applicationContext,
            keyStoreManager = KeystoreManager(),
            onChallengeReceived = { showChallengeNotification() }
        )

        scope.launch {
            bleManager.bleState.collect { state ->
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
                        scheduleReconnect()
                    }

                    is BleState.Error -> {
                        updateNotification("BLE error: ${state.message}")
                        scheduleReconnect()
                    }
                }
            }
        }
    }

    override fun onStartCommand(intent: Intent, flags: Int, startId: Int): Int {
        connectIfPossible()
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
        val notification =
            Notification.Builder(this, CHALLENGE_CHANNEL_ID).setContentTitle("Wrist Hello")
                .setContentText("Signing a challenge").setStyle(
                    Notification.BigTextStyle().bigText(
                        """
                           Signing and replying a challenge...
                           Please check the authentication screen on your PC
                        """.trimIndent()
                    )
                ).setSmallIcon(R.mipmap.ic_launcher)
                .setAutoCancel(true).build()

        manager.notify(CHALLENGE_NOTIFICATION_ID, notification)
    }

    companion object {
        private const val CHANNEL_ID = "ble_foreground"
        private const val CHALLENGE_CHANNEL_ID = "challenge_alerts"
        private const val NOTIFICATION_ID = 1001
        private const val CHALLENGE_NOTIFICATION_ID = 1002
    }
}
