# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# Keep line number info for debugging crashes
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# Room
-keep class * extends androidx.room.RoomDatabase
-keep @androidx.room.Entity class *
-keep @androidx.room.Dao interface *

# Ktor
-keep class io.ktor.** { *; }
-dontwarn io.ktor.**
-keep class kotlin.reflect.jvm.internal.** { *; }

# Koin
-keep class org.koin.** { *; }
-dontwarn org.koin.**

# Keep data classes used by Room
-keep class app.pwhs.blockads.data.** { *; }

# Keep VPN service
-keep class app.pwhs.blockads.service.** { *; }

# Go tunnel (gomobile): generated bindings are looked up by name from Go over
# JNI (tunnel.* classes, the go.Seq runtime and anything implementing a bound
# interface, e.g. callbacks passed into the engine).
-keep class tunnel.** { *; }
-keep interface tunnel.** { *; }
-keep class go.** { *; }
-keep class * implements tunnel.** { *; }
-dontwarn go.**

# Root Proxy / Root WireGuard: service actions are sent by name (am start-foreground-service
# -a app.pwhs.blockads.ROOT_START / ROOT_WG_SET) and helpers are exec'd from nativeLibraryDir;
# the service package is kept above. Receivers referenced from the manifest are kept by AAPT.
-keep class app.pwhs.blockads.receiver.** { *; }
-keep class app.pwhs.blockads.widget.** { *; }

# kotlinx.serialization: keep generated serializers of app classes
-keepattributes *Annotation*, InnerClasses
-keepclassmembers @kotlinx.serialization.Serializable class app.pwhs.blockads.** {
    *** Companion;
    *** INSTANCE;
    kotlinx.serialization.KSerializer serializer(...);
}
-keep,includedescriptorclasses class app.pwhs.blockads.**$$serializer { *; }

# Enums restored by name (DataStore prefs store enum names)
-keepclassmembers enum app.pwhs.blockads.** {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# Coroutines
-dontwarn kotlinx.coroutines.**

-assumenosideeffects class org.slf4j.Logger {
    public *** debug(...);
    public *** info(...);
    public *** trace(...);
}

