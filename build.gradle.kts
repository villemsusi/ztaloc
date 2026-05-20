// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
}

tasks.register<Exec>("runZtaTimingTest") {
    group = "verification"
    description = "Runs the ZTA on-device timing test and prints timing output."
    finalizedBy("printZtaTimingResults")

    val gradleCommand = if (System.getProperty("os.name").contains("Windows", ignoreCase = true)) {
        "gradlew.bat"
    } else {
        "./gradlew"
    }
    workingDir = rootDir
    commandLine(
        gradleCommand,
        ":ztaloc:connectedDebugAndroidTest",
        "-Pandroid.testInstrumentationRunnerArguments.class=com.example.ztaloc.ZtaWorkflowTimingInstrumentedTest"
    )
}

tasks.register("printZtaTimingResults") {
    group = "verification"
    description = "Prints ZTA timing output from the latest connected Android test log."

    doLast {
        val logFile = fileTree(rootDir) {
            include("ztaloc/build/outputs/androidTest-results/connected/debug/**/logcat-com.example.ztaloc.ZtaWorkflowTimingInstrumentedTest-fullRequestResponseWorkflow_logsTimings.txt")
        }
            .files
            .maxByOrNull { it.lastModified() }
            ?: error("ZTA timing log file was not found after the connected test run.")

        logger.lifecycle("ZTA timing log: ${logFile.absolutePath}")
        val timingLines = logFile.readLines()
            .filter { it.contains("ZTA_TIMING_RUN") || it.contains("ZTA_TIMING_SUMMARY") }

        if (timingLines.isEmpty()) {
            logger.lifecycle("No ZTA_TIMING_* lines were found in the timing log.")
        } else {
            timingLines.forEach { line ->
                val message = line.substringAfter("System.out:", line).trim()
                logger.lifecycle(message)
            }
        }
    }
}
