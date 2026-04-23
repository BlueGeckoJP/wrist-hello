/* While this template provides a good starting point for using Wear Compose, you can always
 * take a look at https://github.com/android/wear-os-samples/tree/main/ComposeStarter to find the
 * most up to date changes to the libraries and their usages.
 */

package me.bluegecko.wristhello.presentation

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.RequiresPermission
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.wear.compose.foundation.pager.HorizontalPager
import androidx.wear.compose.foundation.pager.rememberPagerState
import androidx.wear.compose.material3.AnimatedPage
import androidx.wear.compose.material3.AppScaffold
import androidx.wear.compose.material3.EdgeButton
import androidx.wear.compose.material3.EdgeButtonSize
import androidx.wear.compose.material3.HorizontalPageIndicator
import androidx.wear.compose.material3.HorizontalPagerScaffold
import androidx.wear.compose.material3.PagerScaffoldDefaults
import androidx.wear.compose.material3.Text
import androidx.wear.compose.ui.tooling.preview.WearPreviewDevices
import androidx.wear.compose.ui.tooling.preview.WearPreviewFontScales
import me.bluegecko.wristhello.presentation.theme.WristHelloTheme

class MainActivity : ComponentActivity() {
    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ContextCompat.startForegroundService(
            this,
            Intent(this, ForegroundService::class.java)
        )
        setContent {
            WearApp()
        }
    }
}

@Composable
@RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
fun WearApp(viewModel: MainViewModel = viewModel()) {
    val bleState by viewModel.bleState.collectAsStateWithLifecycle()
    val context = LocalContext.current

    val publicKeyQrCode = remember {
        generateQrCode(viewModel.getPublicKey().joinToString("") { "%02x".format(it) })
    }

    val requestPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted: Boolean ->
        if (isGranted) viewModel.connect()
    }

    LaunchedEffect(Unit) {
        if (ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.BLUETOOTH_CONNECT
            ) == PackageManager.PERMISSION_GRANTED
        ) {
            viewModel.connect()
        } else {
            requestPermissionLauncher.launch(Manifest.permission.BLUETOOTH_CONNECT)
        }

        if (ContextCompat.checkSelfPermission(
                context, Manifest.permission.POST_NOTIFICATIONS
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    WristHelloTheme {
        AppScaffold {
            val pagerState = rememberPagerState(pageCount = { 2 })
            HorizontalPagerScaffold(
                pagerState = pagerState,
                pageIndicator = {
                    HorizontalPageIndicator(pagerState = pagerState)
                }

            ) {
                HorizontalPager(
                    state = pagerState,
                    flingBehavior = PagerScaffoldDefaults.snapWithSpringFlingBehavior(
                        state = pagerState
                    )
                ) { page ->
                    AnimatedPage(pageIndex = page, pagerState = pagerState) {
                        when (page) {
                            0 -> {
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

                            1 -> {
                                Image(
                                    bitmap = publicKeyQrCode.asImageBitmap(),
                                    contentDescription = "Public Key QR Code",
                                    modifier = Modifier
                                        .fillMaxSize()
                                        .padding(56.dp)
                                )
                            }
                        }
                    }
                }
            }
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
