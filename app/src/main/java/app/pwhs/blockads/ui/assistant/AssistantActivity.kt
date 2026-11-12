package app.pwhs.blockads.ui.assistant

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import app.pwhs.blockads.MainActivity
import app.pwhs.blockads.ui.theme.BlockadsTheme

class AssistantActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            BlockadsTheme {
                AssistantScreen(
                    onDismiss = { finish() },
                    onOpenLogs = {
                        val intent = Intent(this, MainActivity::class.java).apply {
                            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                            putExtra("navigate_to", "logs")
                        }
                        startActivity(intent)
                        finish()
                    }
                )
            }
        }
    }
}
