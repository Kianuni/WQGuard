//
//  main.swift
//  wqguard-cli
//
//  Command-line interface entrypoint for WQGuard security scanner.
//  100% read-only, zero-dependency Darwin CLI tool.
//

import Foundation
import Darwin
import WQGuardCore

let exitCode = await CLICommandRunner.run(arguments: CommandLine.arguments)
exit(exitCode)
