# Android 编译
```cmake
export PATH=/opt/toolchains/android/android-ndk-r22b/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH
export ANDROID_NDK_HOME=/opt/toolchains/android/android-ndk-r22b

cmake -DCMAKE_TOOLCHAIN_FILE=/opt/toolchains/android/android-ndk-r22b/build/cmake/android.toolchain.cmake
-DCMAKE_SYSTEM_NAME=Android
-DCMAKE_SYSTEM_VERSION=21
-DANDROID_NDK=/opt/toolchains/android/android-ndk-r22b/
-DANDROID_PLATFORM=android-21
-DANDROID_ABI=arm64-v8a
-DCMAKE_ANDROID_ARCH_ABI=arm64-v8a
-DCMAKE_C_FLAGS="-fpic -fexceptions -frtti"
-DCMAKE_CXX_FLAGS="-fpic -fexceptions -frtti"
-DANDROID_STL=c++_static
```