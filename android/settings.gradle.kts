pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "cosign"
include(":cosign")
include(":nip55tester")
// The QRST core and relay layer, shared with QRST Signer: the submodule, at the commit recorded here.
includeBuild("../qr-secret-transfer/kotlin")
