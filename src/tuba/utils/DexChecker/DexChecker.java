package tuba.utils.DexChecker;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.preference.PreferenceManager;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * User: tuba
 * Date: 12.02.13
 * Time: 22:25
 */
public final class DexChecker {
    // Change this value!
    private static final String SALT = "ENTER_RANDOM_GENERATED SALT_HERE";

    private static final String TAG = "DexChecker";
    private static final String DALVIK_CACHE_PATH = "/data/dalvik-cache/";
    private static final String SELECT_RUNTIME_PROPERTY = "persist.sys.dalvik.vm.lib";
    private static final String LIB_DALVIK = "libdvm.so";
    private static final String LIB_ART = "libart.so";
    private static final String LIB_ART_D = "libartd.so";

    public static boolean checkDexCache(Context context) throws IOException {
        String vm = getCurrentRuntimeValue();
        if (TextUtils.isEmpty(vm) || vm.contains("ART")) {
            return true;
        }

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        String androidId = Settings.System.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID);

        String sourceDir = context.getApplicationInfo().sourceDir;
        // Check app time
        long savedAppTime = prefs.getLong("app-time", -1);
        if (savedAppTime != getAppInstalledTime(context)) {
            prefs.edit().remove("checksum-app").commit();
        }

        Log.d(TAG, "Check installation : ");
        byte[] apkChecksum;
        if (!prefs.contains("checksum-app")) {
            Log.d(TAG, "Load DEX : " + sourceDir);
            String localDir = context.getFilesDir().getAbsolutePath();

            String className = "ZGFsdmlrLnN5c3RlbS5EZXhGaWxl";
            String methodName = "bG9hZERleA==";

            try {
                Class clazz = Class.forName(new String(Base64.decode(className, Base64.DEFAULT)));
                Method m = clazz.getDeclaredMethod(new String(Base64.decode(methodName, Base64.DEFAULT)),
                        String.class, String.class, int.class);
                m.invoke(null, sourceDir, localDir + "/test.dex", 0);
            } catch (Throwable e) {
                Log.e(TAG, e.getMessage(), e);
                return false;
            }

            try {
                apkChecksum = calculateDalvikChecksum(localDir + "/test.dex", (androidId + SALT).getBytes());
            } catch (Throwable t) {
                Log.e(TAG, "Probably not Dalvik VM", t);
                return false;
            }

            new File(localDir + "/classes.dex").delete();

            SharedPreferences.Editor editor = prefs.edit();
            editor.putString("checksum-app", new String(Base64.encode(apkChecksum, Base64.DEFAULT)));
            editor.putLong("app-time", getAppInstalledTime(context));
            editor.commit();
        } else {
            apkChecksum = Base64.decode(prefs.getString("checksum-app", ""), Base64.DEFAULT);
        }

        String odex = sourceDir.replace(".apk", ".odex");
        Log.d(TAG, "ODEX :" + odex);
        if (new File(odex).exists()) {
            byte[] odexChecksum = calculateDalvikChecksum(odex, (androidId + SALT).getBytes());
            if (!Arrays.equals(odexChecksum, apkChecksum)) {
                Log.d(TAG, "Odex checksum is NOT MATCH! ");
                prefs.edit().remove("checksum-app").commit();
                return false;
            }
        }

        String dexCache = DALVIK_CACHE_PATH + sourceDir.substring(1).replace('/', '@') + "@classes.dex";
        byte[] dexChecksum = calculateDalvikChecksum(dexCache, (androidId + SALT).getBytes());
        if (!Arrays.equals(dexChecksum, apkChecksum)) {
            Log.d(TAG, "Dex cache checksum is NOT MATCH! ");
            prefs.edit().remove("checksum-app").commit();
            return false;
        }

        Log.d(TAG, "Checksum is VALID! ");

        return true;
    }

    protected static long getAppInstalledTime(Context context) {
        try {
            PackageManager pm = context.getPackageManager();
            ApplicationInfo appInfo = pm.getApplicationInfo(context.getPackageName(), 0);
            String appFile = appInfo.sourceDir;

            return new File(appFile).lastModified();
        } catch (PackageManager.NameNotFoundException e) {
            if (Log.isLoggable(TAG, Log.DEBUG))
                e.printStackTrace();

            Log.e(TAG, e.getLocalizedMessage(), e);
        }

        return -1;
    }

    protected static byte[] calculateDalvikChecksum(String filename, byte[] salt) throws IOException {
        return calculateDalvikChecksum(new FileInputStream(filename), salt);
    }

    public static byte[] calculateDalvikChecksum(InputStream is, byte[] salt) throws IOException {
        // Skip to optOffset
        is.skip(24);

        int optOffset = Utils.readLeInt(is);

        MessageDigest complete;
        try {
            complete = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            if (Log.isLoggable(TAG, Log.DEBUG))
                e.printStackTrace();

            Log.e(TAG, e.getLocalizedMessage(), e);

            return null;
        }
        if (salt != null && salt.length > 0) {
            complete.update(salt);
        }

        // Skip length, flag and checksum
        is.skip(12);

        // Update hash by data
        Utils.hashBlock(is, complete, optOffset - 40);

        // Look on opt data
        String block = Utils.readLeString(is, 4);

        // Update by ClassLookup
        if (block.equals("CLKP")) {
            Utils.hashBlock(is, complete, Utils.readLeInt(is));
        }

        return complete.digest();
    }

    private static String getCurrentRuntimeValue() {
        try {
            Class<?> systemProperties = Class.forName("android.os.SystemProperties");
            try {
                Method get = systemProperties.getMethod("get", String.class, String.class);
                if (get == null) {
                    return null;
                }
                try {
                    final String value = (String) get.invoke(systemProperties, SELECT_RUNTIME_PROPERTY, "Dalvik");
                    if (LIB_DALVIK.equals(value)) {
                        return "Dalvik";
                    } else if (LIB_ART.equals(value)) {
                        return "ART";
                    } else if (LIB_ART_D.equals(value)) {
                        return "ARTD";
                    }

                    return value;
                } catch (Throwable e) {
                    return null;
                }
            } catch (NoSuchMethodException e) {
                return null;
            }
        } catch (ClassNotFoundException e) {
            return null;
        }
    }
}
