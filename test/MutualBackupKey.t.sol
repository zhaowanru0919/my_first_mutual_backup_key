// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {MutualBackupKey} from "../src/MutualBackupKey.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract MutualBackupKeyTest is Test {
    using ECDSA for bytes32;

    MutualBackupKey public mutualBackupKey;

    // 注册测试账户： Wanru 和 KJ
    address public userWanru = address(0x1111);
    address public userKJ = address(0x2222);

    // 签名用私钥
    uint256 public privateKeyWanru = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef;
    uint256 public privateKeyKJ = 0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210;

    // 从私钥派生的主钥匙地址
    address public mainKeyWanru;
    address public mainKeyKJ;
    address public backupKeyWanru = address(0xAAA2);
    address public backupKeyKJ = address(0xBBB2);

    function setUp() public {
        //部署合约
        mutualBackupKey = new MutualBackupKey();

        //给测试账户转账
        vm.deal(userWanru, 99 ether);
        vm.deal(userKJ, 9 ether);

        // 从私钥派生主钥匙地址
        mainKeyWanru = vm.addr(privateKeyWanru);
        mainKeyKJ = vm.addr(privateKeyKJ);
    }

    /**
     * 用户注册
     */
    function testRegisterUser() public {
        // userWanru 注册
        vm.prank(userWanru);
        mutualBackupKey.registerUser(mainKeyWanru, backupKeyWanru);

        // 验证用户信息
        (address main, address backup, bool active, address partner) = mutualBackupKey.getUserDetails(userWanru);
        assertEq(main, mainKeyWanru);
        assertEq(backup, backupKeyWanru);
        assertTrue(active);
        assertEq(partner, address(0));

        //测试重复注册
        vm.prank(userWanru);
        vm.expectRevert(MutualBackupKey.UserAlreadyExists.selector);
        mutualBackupKey.registerUser(mainKeyWanru, backupKeyWanru);
    }

    /** 
     * 绑定Wanru和KJ为伙伴
     */
    function testMutualPartner() public {
        // 先注册Wanru 和 KJ 两个用户
        vm.prank(userWanru);
        mutualBackupKey.registerUser(mainKeyWanru, backupKeyWanru);

        vm.prank(userKJ);
        mutualBackupKey.registerUser(mainKeyKJ, backupKeyKJ);

        // Wanru 绑定 KJ
        vm.prank(userWanru);
        mutualBackupKey.bindMutualPartner(userKJ);

        //验证绑定关系
        (,,, address partnerKJ) = mutualBackupKey.getUserDetails(userWanru);
        (,,, address partnerWanru) = mutualBackupKey.getUserDetails(userKJ);
        assertEq(partnerKJ, userKJ);
        assertEq(partnerWanru, userWanru);

        //测试重复绑定
        vm.prank(userWanru);
        vm.expectRevert(MutualBackupKey.PartnerAlreadyBound.selector);
        mutualBackupKey.bindMutualPartner(userKJ);
    }

    /** 
     * 测试激活备用钥匙
     */
    function testActivatedBackupKey_Success() public {
        // 注册用户 Wanru & KJ
        vm.prank(userWanru);
        mutualBackupKey.registerUser(mainKeyWanru, backupKeyWanru);

        vm.prank(userKJ);
        mutualBackupKey.registerUser(mainKeyKJ, backupKeyKJ);

        // 互相绑定为小伙伴
        vm.prank(userWanru);
        mutualBackupKey.bindMutualPartner(userKJ);

        // 生成 Wanru 主钥匙的签名
        bytes32 messageHash = mutualBackupKey.getActivationMessageHash(userWanru);
        bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(messageHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKeyWanru, ethSignedHash);
        bytes memory signatureWanru = abi.encodePacked(r, s, v);

        // KJ 调用激活 Wanru的备用钥匙
        vm.prank(userKJ);
        vm.expectEmit(true, false, false, false);
        emit MutualBackupKey.BackupKeyActivated(userWanru, userKJ, backupKeyWanru);
        mutualBackupKey.activateBackupKey(userWanru, signatureWanru);

        // 验证激活结果
        (address newMainKeyWanru, address newBackupKeyWanru,, ) = mutualBackupKey.getUserDetails(userWanru);
        assertEq(newMainKeyWanru, backupKeyWanru);
        assertEq(newBackupKeyWanru, mainKeyWanru);

        // 生成 KJ 主钥匙的签名
        bytes32 messageHashKJ = mutualBackupKey.getActivationMessageHash(userKJ);
        bytes32 ethSignedHashKJ = MessageHashUtils.toEthSignedMessageHash(messageHashKJ);
        (uint8 vKJ, bytes32 rKJ, bytes32 sKJ) = vm.sign(privateKeyKJ, ethSignedHashKJ);
        bytes memory signatureKJ = abi.encodePacked(rKJ, sKJ, vKJ);

        // Wanru 激活 KJ的备用钥匙
        vm.prank(userWanru);
        vm.expectEmit(true, false, false, false);
        emit MutualBackupKey.BackupKeyActivated(userKJ, userWanru, backupKeyKJ);
        mutualBackupKey.activateBackupKey(userKJ, signatureKJ);

        // 验证激活结果
        (address newMainKeyKJ, address newBackupKeyKJ,, ) = mutualBackupKey.getUserDetails(userKJ);
        assertEq(newMainKeyKJ, backupKeyKJ);
        assertEq(newBackupKeyKJ, mainKeyKJ);
    }
}
