package me.bluegecko.wristhello.presentation

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED -> {
                ContextCompat.startForegroundService(
                    context,
                    Intent(context, ForegroundService::class.java)
                )
            }
        }
    }
}