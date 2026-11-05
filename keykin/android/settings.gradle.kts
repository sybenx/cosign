// keykin-android: the Keykin device library for Android (step B2), and a demo app that drives it.
pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories { google(); mavenCentral() }
}
rootProject.name = "keykin-android"
include(":keykin", ":demo")
