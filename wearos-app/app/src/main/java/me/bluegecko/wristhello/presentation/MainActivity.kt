/* While this template provides a good starting point for using Wear Compose, you can always
 * take a look at https://github.com/android/wear-os-samples/tree/main/ComposeStarter to find the
 * most up to date changes to the libraries and their usages.
 */

package me.bluegecko.wristhello.presentation

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.RequiresPermission
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.wear.compose.material3.AppScaffold
import androidx.wear.compose.material3.EdgeButton
import androidx.wear.compose.material3.EdgeButtonSize
import androidx.wear.compose.material3.ScreenScaffold
import androidx.wear.compose.material3.Text
import androidx.wear.compose.ui.tooling.preview.WearPreviewDevices
import androidx.wear.compose.ui.tooling.preview.WearPreviewFontScales
import me.bluegecko.wristhello.presentation.theme.WristHelloTheme

class MainActivity : ComponentActivity() {
    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            WearApp()
        }
    }
}

@Composable
@RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
fun WearApp() {

    WristHelloTheme {
        AppScaffold {
            MainScreen()
        }
    }
}

@RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
@WearPreviewDevices
@WearPreviewFontScales
@Composable
fun DefaultPreview() {
    WearApp()
}

@Composable
@RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
fun MainScreen(viewModel: MainViewModel = viewModel()) {

    val bleState by viewModel.bleState.collectAsStateWithLifecycle()
    val context = LocalContext.current

    val requestPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted: Boolean ->
        if (isGranted) viewModel.connect()
    }

    LaunchedEffect(Unit) {
        val permission = Manifest.permission.BLUETOOTH_CONNECT
        if (ContextCompat.checkSelfPermission(
                context,
                permission
            ) == PackageManager.PERMISSION_GRANTED
        ) {
            viewModel.connect()
        } else {
            requestPermissionLauncher.launch(permission)
        }
    }

    ScreenScaffold {
        Box(modifier = Modifier.fillMaxSize()) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(16.dp),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                when (val state = bleState) {
                    is BleState.Disconnected -> Text("Disconnected")
                    is BleState.Connecting -> Text("Connecting...")
                    is BleState.Connected -> Text("Connected")
                    is BleState.Error -> Text("Error: ${state.message}")
                }
            }

            EdgeButton(
                onClick = {
                    if (bleState is BleState.Connected) viewModel.disconnect()
                    viewModel.connect()
                },
                enabled = bleState != BleState.Connecting,
                buttonSize = EdgeButtonSize.ExtraSmall,
                modifier = Modifier.align(Alignment.BottomCenter)
            ) {
                Text("Reconnect")
            }
        }
    }
}

