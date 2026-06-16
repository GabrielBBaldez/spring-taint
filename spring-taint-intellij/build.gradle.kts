plugins {
    id("org.jetbrains.kotlin.jvm") version "2.1.20"
    id("org.jetbrains.intellij.platform") version "2.16.0"
}

group = "io.github.gabrielbbaldez.springtaint"
version = "0.1.0"

repositories {
    mavenCentral()
    intellijPlatform {
        defaultRepositories()
    }
}

dependencies {
    intellijPlatform {
        // IntelliJ IDEA Community is enough: the analyzer targets Java/Spring.
        intellijIdeaCommunity("2024.3.1")
        bundledPlugin("com.intellij.java")
    }
    implementation("com.google.code.gson:gson:2.11.0")
}

// Bundle the analyzer's shaded jar inside the plugin; it is extracted to a temp file and
// run as a separate process at scan time. The engine is a Maven module, so build it first:
//   mvn -pl spring-taint-engine -am package
tasks.processResources {
    val engineJar = file("../spring-taint-engine/target/spring-taint-all.jar")
    doFirst {
        if (!engineJar.exists()) {
            throw GradleException(
                "Engine jar not found: $engineJar -- build it first with " +
                    "`mvn -pl spring-taint-engine -am package` from the repo root.",
            )
        }
    }
    from(engineJar) { into("engine") }
}

intellijPlatform {
    pluginConfiguration {
        name = "Spring Taint"
        version = project.version.toString()
        ideaVersion {
            sinceBuild = "243"
        }
    }
}

kotlin {
    jvmToolchain(21)
}
