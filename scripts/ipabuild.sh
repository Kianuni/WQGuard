#!/usr/bin/env bash
# ==============================================================================
# WQGuard Standalone IPA Packaging Pipeline
# Builds WQGuard.app for arm64 iOS and packages a production-grade,
# ad-hoc/ldid signed .ipa without requiring a paid Apple Developer certificate.
# Compatible with macOS host Xcode 15+ / 16+ / 27+ and TrollStore / AltStore / Sideloadly.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ -f "$SCRIPT_DIR/../WQGuard.xcodeproj/project.pbxproj" ]]; then
    REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
elif [[ -f "$PWD/WQGuard.xcodeproj/project.pbxproj" ]]; then
    REPO_ROOT="$PWD"
elif [[ -f "$PWD/WQGuard/WQGuard.xcodeproj/project.pbxproj" ]]; then
    REPO_ROOT="$PWD/WQGuard"
elif command -v git >/dev/null 2>&1 && git rev-parse --show-toplevel >/dev/null 2>&1 && [[ -f "$(git rev-parse --show-toplevel)/WQGuard/WQGuard.xcodeproj/project.pbxproj" ]]; then
    REPO_ROOT="$(git rev-parse --show-toplevel)/WQGuard"
elif command -v git >/dev/null 2>&1 && git rev-parse --show-toplevel >/dev/null 2>&1 && [[ -f "$(git rev-parse --show-toplevel)/WQGuard.xcodeproj/project.pbxproj" ]]; then
    REPO_ROOT="$(git rev-parse --show-toplevel)"
else
    REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
fi
cd "$REPO_ROOT"

APPLICATION_NAME="WQGuard"
ENTITLEMENTS_FILE="$REPO_ROOT/WQGuard/Resources/WQGuard.entitlements"
INFO_PLIST="$REPO_ROOT/WQGuard/Resources/Info.plist"
BUILD_CONFIGURATION="Release"
OUTPUT_DIR="$REPO_ROOT/build"
FINAL_IPA_NAME=""
DO_CLEAN=0
SKIP_TESTS="${WQ_SKIP_TESTS:-0}"
BUILD_SUCCESS=0
SIGNING_TOOL="codesign"

print_usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

WQGuard Standalone IPA Packaging & Ad-Hoc Signing Pipeline

Options:
  -o, --output <path>            Specify output IPA file path (e.g. WQGuard.ipa or /path/to/app.ipa)
  -c, --configuration <config>   Build configuration: Release or Debug (default: Release)
      --clean                    Clean previous build artifacts and run 'clean build' in xcodebuild
      --debug                    Shorthand for '--configuration Debug'
  -s, --skip-tests               Skip running pre-flight host unit tests (can also set WQ_SKIP_TESTS=1)
  -h, --help                     Show this usage manual and exit 0

Exit Codes:
  0     Build and IPA packaging succeeded (or help requested)
  1     Compilation, code signing, or verification failure
  2     Usage error or invalid CLI argument
EOF
}

# Parse flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)
            print_usage
            exit 0
            ;;
        --clean)
            DO_CLEAN=1
            shift
            ;;
        --debug)
            BUILD_CONFIGURATION="Debug"
            shift
            ;;
        --configuration|-c)
            if [[ $# -lt 2 || -z "${2:-}" ]]; then
                echo "[-] Error: $1 requires a configuration argument ('Release' or 'Debug')." >&2
                print_usage >&2
                exit 2
            fi
            case "$2" in
                Release|Debug)
                    BUILD_CONFIGURATION="$2"
                    ;;
                release)
                    BUILD_CONFIGURATION="Release"
                    ;;
                debug)
                    BUILD_CONFIGURATION="Debug"
                    ;;
                *)
                    echo "[-] Error: Invalid configuration '$2'. Expected 'Release' or 'Debug'." >&2
                    print_usage >&2
                    exit 2
                    ;;
            esac
            shift 2
            ;;
        --skip-tests|-s)
            SKIP_TESTS=1
            shift
            ;;
        --output|-o)
            if [[ $# -lt 2 || -z "${2:-}" ]]; then
                echo "[-] Error: $1 requires an output file path argument." >&2
                print_usage >&2
                exit 2
            fi
            FINAL_IPA_NAME="$2"
            shift 2
            ;;
        *)
            echo "[-] Error: Unknown argument: $1" >&2
            print_usage >&2
            exit 2
            ;;
    esac
done

cleanup() {
    local exit_code=$?
    if [[ ${BUILD_SUCCESS} -ne 1 ]]; then
        echo "[-] Cleaning temporary build artifacts..." >&2
        if [[ -d "$OUTPUT_DIR" ]]; then
            rm -rf "$OUTPUT_DIR/DerivedData" "$OUTPUT_DIR/Payload" "$OUTPUT_DIR/${APPLICATION_NAME}.app" "$OUTPUT_DIR/temp.ipa" "$OUTPUT_DIR"/verify.*
            if [[ -n "${FINAL_IPA_NAME:-}" && "$FINAL_IPA_NAME" != "$OUTPUT_DIR"/* && "$FINAL_IPA_NAME" != "$OUTPUT_DIR" ]]; then
                rm -rf "$OUTPUT_DIR"
            else
                rmdir "$OUTPUT_DIR" 2>/dev/null || true
            fi
        fi
    fi
    exit $exit_code
}

trap "exit 130" INT
trap "exit 143" TERM
trap cleanup EXIT

# Extract version and bundle ID from Info.plist and project
APP_VERSION=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$INFO_PLIST" 2>/dev/null || echo "1.0.0")
APP_BUILD=$(/usr/libexec/PlistBuddy -c "Print :CFBundleVersion" "$INFO_PLIST" 2>/dev/null || echo "1")
BUNDLE_ID=$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$INFO_PLIST" 2>/dev/null || echo "")
if [[ -z "$BUNDLE_ID" || "$BUNDLE_ID" == *"\$"* ]]; then
    BUNDLE_ID=$(grep -m 1 "PRODUCT_BUNDLE_IDENTIFIER" "$REPO_ROOT/WQGuard.xcodeproj/project.pbxproj" 2>/dev/null | sed -E 's/.*= *([^;]+);.*/\1/' | tr -d ' "\t' || echo "")
fi
if [[ -z "$BUNDLE_ID" ]]; then
    BUNDLE_ID="com.wqguard.app"
fi

if [[ -z "$FINAL_IPA_NAME" ]]; then
    if [[ "$BUILD_CONFIGURATION" == "Debug" ]]; then
        FINAL_IPA_NAME="$REPO_ROOT/${APPLICATION_NAME}_v${APP_VERSION}_debug.ipa"
    else
        FINAL_IPA_NAME="$REPO_ROOT/${APPLICATION_NAME}_v${APP_VERSION}.ipa"
    fi
elif [[ -d "$FINAL_IPA_NAME" || "$FINAL_IPA_NAME" == */ ]]; then
    mkdir -p "$FINAL_IPA_NAME"
    FINAL_IPA_NAME="$FINAL_IPA_NAME/${APPLICATION_NAME}_v${APP_VERSION}.ipa"
fi

# Ensure destination directory exists and canonicalize destination path
mkdir -p "$(dirname "$FINAL_IPA_NAME")"
FINAL_IPA_DIR="$(cd -- "$(dirname "$FINAL_IPA_NAME")" && pwd)"
FINAL_IPA_NAME="$FINAL_IPA_DIR/$(basename "$FINAL_IPA_NAME")"

echo "=========================================================="
echo "🛡️  $APPLICATION_NAME Packaging Pipeline"
echo "    Version:       v$APP_VERSION (Build $APP_BUILD)"
echo "    Bundle ID:     $BUNDLE_ID"
echo "    Configuration: $BUILD_CONFIGURATION"
echo "    Clean Build:   $([[ $DO_CLEAN -eq 1 ]] && echo 'Yes' || echo 'No')"
echo "    Destination:   $FINAL_IPA_NAME"
echo "=========================================================="

# Pre-flight host tests (prevent building broken artifact)
if [[ "${SKIP_TESTS}" != "1" ]]; then
    echo "[*] Step 1/5: Running host unit tests (swift test)..."
    swift test --disable-sandbox -q || {
        echo "[-] Host unit tests failed. Aborting IPA build." >&2
        exit 1
    }
else
    echo "[*] Step 1/5: Skipping host unit tests (--skip-tests active)."
fi

# Clean previous build artifacts
if [[ "$FINAL_IPA_NAME" == "$OUTPUT_DIR"/* || "$FINAL_IPA_NAME" == "$OUTPUT_DIR" ]]; then
    rm -rf "$OUTPUT_DIR/DerivedData" "$OUTPUT_DIR/Payload" "$OUTPUT_DIR/${APPLICATION_NAME}.app" "$OUTPUT_DIR/temp.ipa" "$OUTPUT_DIR"/verify.*
else
    rm -rf "$OUTPUT_DIR"
fi
mkdir -p "$OUTPUT_DIR/DerivedData"

XCODE_ACTION="build"
if [[ $DO_CLEAN -eq 1 ]]; then
    XCODE_ACTION="clean build"
fi

echo "[*] Step 2/5: Compiling via xcodebuild ($XCODE_ACTION, headless, no dev cert required)..."
xcodebuild -project "$REPO_ROOT/WQGuard.xcodeproj" \
    -scheme "$APPLICATION_NAME" \
    -configuration "$BUILD_CONFIGURATION" \
    -destination 'generic/platform=iOS' \
    -derivedDataPath "$OUTPUT_DIR/DerivedData" \
    $XCODE_ACTION \
    CODE_SIGNING_ALLOWED=NO \
    CODE_SIGNING_REQUIRED=NO \
    CODE_SIGN_IDENTITY="" \
    CODE_SIGN_ENTITLEMENTS=""

BUILT_APP="$OUTPUT_DIR/DerivedData/Build/Products/${BUILD_CONFIGURATION}-iphoneos/${APPLICATION_NAME}.app"
if [[ ! -d "$BUILT_APP" ]]; then
    echo "[-] Error: Expected built app at $BUILT_APP does not exist!" >&2
    exit 1
fi

APP_TARGET="$OUTPUT_DIR/${APPLICATION_NAME}.app"
rm -rf "$APP_TARGET"
cp -R "$BUILT_APP" "$APP_TARGET"

echo "[*] Step 3/5: Sanitizing code signature and provisioning profiles..."
rm -rf "$APP_TARGET/_CodeSignature"
rm -f "$APP_TARGET/embedded.mobileprovision"

echo "[*] Step 4/5: Injecting entitlements ($ENTITLEMENTS_FILE)..."
if command -v ldid >/dev/null 2>&1; then
    echo "    Using ldid for ad-hoc pseudo-signing..."
    ldid -S"$ENTITLEMENTS_FILE" "$APP_TARGET"
    SIGNING_TOOL="ldid"
else
    echo "    Using codesign for ad-hoc signing with DER generation..."
    codesign --force --sign - \
        --entitlements "$ENTITLEMENTS_FILE" \
        --generate-entitlement-der \
        --timestamp=none \
        "$APP_TARGET"
    SIGNING_TOOL="codesign"
fi

echo "[*] Step 5/5: Packaging into IPA container..."
PAYLOAD_DIR="$OUTPUT_DIR/Payload"
mkdir -p "$PAYLOAD_DIR"
cp -R "$APP_TARGET" "$PAYLOAD_DIR/${APPLICATION_NAME}.app"

IPA_TEMP="$OUTPUT_DIR/temp.ipa"
rm -f "$IPA_TEMP"
(cd "$OUTPUT_DIR" && zip -9qry "$IPA_TEMP" Payload)

echo "[*] Verifying IPA package integrity..."
unzip -tqq "$IPA_TEMP"

# Verify binary and entitlements inside the archive
VERIFY_DIR=$(mktemp -d "$OUTPUT_DIR/verify.XXXXXX")
unzip -q "$IPA_TEMP" -d "$VERIFY_DIR"
VERIFY_APP="$VERIFY_DIR/Payload/${APPLICATION_NAME}.app"

if [[ ! -x "$VERIFY_APP/$APPLICATION_NAME" ]]; then
    echo "[-] Verification failed: Executable missing or non-executable!" >&2
    rm -rf "$VERIFY_DIR"
    exit 1
fi

if [[ "$SIGNING_TOOL" == "codesign" ]]; then
    codesign --verify --deep --strict "$VERIFY_APP"
    echo "[+] Code signature verification passed (codesign ad-hoc)."
else
    echo "[+] Verified ldid pseudo-signed executable presence."
fi
rm -rf "$VERIFY_DIR"

mv -f "$IPA_TEMP" "$FINAL_IPA_NAME"

# Guard cleanup so destination inside OUTPUT_DIR is not deleted
if [[ "$FINAL_IPA_NAME" == "$OUTPUT_DIR"/* || "$FINAL_IPA_NAME" == "$OUTPUT_DIR" ]]; then
    rm -rf "$OUTPUT_DIR/DerivedData" "$OUTPUT_DIR/Payload" "$APP_TARGET" "$OUTPUT_DIR"/verify.*
    if [[ "$FINAL_IPA_NAME" != "$IPA_TEMP" ]]; then
        rm -f "$IPA_TEMP"
    fi
else
    rm -rf "$OUTPUT_DIR"
fi

BUILD_SUCCESS=1

echo "=========================================================="
echo "✅ Build Complete!"
echo "   Output IPA: $FINAL_IPA_NAME"
echo "   File Size:  $(du -h "$FINAL_IPA_NAME" | cut -f1)"
echo "=========================================================="
