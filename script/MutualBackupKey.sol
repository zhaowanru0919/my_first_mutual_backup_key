// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";
import {MutualBackupKey} from "../src/MutualBackupKey.sol";

contract MutualBackupKeyScript is Script {
    MutualBackupKey public mutualBackupKey;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        mutualBackupKey = new MutualBackupKey();

        vm.stopBroadcast();
    }
}
