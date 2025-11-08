// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title MutualBackupKey
 * @author Wanru
 * requirement: “做我们的2人签名，互相激活备用钥匙的合约”
 * 两个用户互相激活备用钥匙合约
 * 两个用户互相绑定，激活对方备用钥匙需要另一方的本人签名授权
 */

contract MutualBackupKey is Ownable {
    using ECDSA for bytes32; // 用ECDSA（椭圆曲线数字签名算法）处理32字节数据的签名/验签
    
    //用户结构体
    struct User {
        address mainKey; //主钥匙地址
        address backupKey; //备用钥匙地址
        bool isActive; //账户是否激活
        address mutualPartner; //合作小伙伴地址
    }

    // Solidity 智能合约中的核心数据存储语法
    // 定义一个公开（public）的映射（mapping），将用户地址（address类型）作为唯一键
    // 关联到用户自定义类型（user类型）
    // 用户存储和查询每个地址对应的用户信息
    mapping(address => User) public users; 

    // 定义事件
    // 在区块链中，event 是合约执行时 “写入链上的日志”—— 用来记录关键操作（比如用户绑定、转账、授权），不会影响合约状态，但永久存储在链上，供外部调用和查询
    // 仅值类型支持添加indexed，比如address、uint/int（各种长度）、bool、bytes32 等；
    // 一个事件最多给三个参数添加indexed
    // indexed 是 事件参数的索引修饰符，核心作用是将当前参数标记为可检索的索引，允许后续通过该参数快速过滤，查询对应的事件日志
    // 没有 indexed 的参数：只是事件日志里的 “附加数据”，只能完整读取日志才能看到，无法作为查询条件；
    // 有 indexed 的参数：会被区块链单独建立 “索引目录”，支持按该参数 “精确查询” 或 “过滤筛选”。
    event UserRegistered(address indexed user, address mainKey, address backupKey); 
    event MutualPartnerBound(address indexed userA, address indexed userB);
    event BackupKeyActivated(address indexed user, address activatedBy, address backupKey);
    event BackupKeyUpdated(address indexed user, address newBackupKey);

    //错误定义
    error UserAlreadyExists();
    error UserNotExists();
    error InvalidMainKey();
    error InvalidBackupKey();
    error PartnerNotBound();
    error InvalidSignature();
    error BackupKeyAlreadyActivated();
    error SelfPartnerNotAllowed();
    error PartnerAlreadyBound();

    /**
     * @dev 构造函数 - 初始化合约部署者为管理员
     */
    constructor() Ownable(msg.sender){}

    /**
     * @dev 注册用户（设置主钥匙和初始备用钥匙）
     * @param mainKey 主钥匙地址（必须是用户本人控制的地址）
     * @param backupKey 备用钥匙地址
     */

    function registerUser(address mainKey, address backupKey) external {
        // 异常检测
        if(users[msg.sender].isActive) revert UserAlreadyExists(); //触发异常并回滚
        if(mainKey == address(0)) revert InvalidMainKey(); //如果 mainKey 的值等于「零地址（address[0]）」，就触发异常并回滚
        if(backupKey == address(0) || backupKey == mainKey) revert InvalidBackupKey();

        users[msg.sender] = User({
            mainKey: mainKey,
            backupKey: backupKey,
            isActive: true,
            mutualPartner: address(0)
        });

        //触发事件并记录日志
        emit UserRegistered(msg.sender, mainKey, backupKey);
    }

    /**
     * @dev 双方用户互相绑定为对方的partner
     * @param partner 小伙伴地址
     */
    function bindMutualPartner(address partner) external {
        User storage user = users[msg.sender];
        User storage partnerUser = users[partner];

        if(!user.isActive) revert UserNotExists();
        if(!partnerUser.isActive) revert UserNotExists();
        if(msg.sender == partner) revert SelfPartnerNotAllowed();
        if(user.mutualPartner != address(0)) revert PartnerAlreadyBound();
        if(partnerUser.mutualPartner != address(0)) revert PartnerAlreadyBound();

        // 互相设置为对方的partner
        user.mutualPartner = partner;
        partnerUser.mutualPartner = msg.sender;

        emit MutualPartnerBound(msg.sender, partner);
    }

    /**
     * @dev 更新备用钥匙，只能由主钥匙或者本人？？？？调用
     * @param newBackupKey, 新的备用钥匙地址
     */
    function updateBackupKey(address newBackupKey) external {
        User storage user = users[msg.sender];
        
        if(!user.isActive) revert UserNotExists();
        if(newBackupKey == address(0) || newBackupKey == user.mainKey) revert InvalidBackupKey();

        // 更新备用钥匙
        user.backupKey = newBackupKey;

        emit BackupKeyUpdated(msg.sender, newBackupKey);
    }

    /**
     * @dev 激活备用钥匙（需小伙伴签名授权）
     * @param targetUser，需要被激活备用钥匙的用户
     * @param partnerSignature，小伙伴授权激活备用钥匙的签名
     */
    function activateBackupKey(address targetUser, bytes memory partnerSignature) external{
        User storage target = users[targetUser];
        User storage caller = users[msg.sender];

        // 验证目标用户和调用者
        if(!target.isActive) revert UserNotExists();
        if(!caller.isActive) revert UserNotExists();

        // 验证双方互为对方的partner
        if(target.mutualPartner != msg.sender || caller.mutualPartner != targetUser) {
            revert PartnerNotBound();
        }
        
        // 验证签证（签名者必须是目标用户的主钥匙）
        // ECDSA 算法的验证签名的核心流程，目的 - 验证签名（partnerSignature）是否由合法主体签署，且签名的内容是“激活target user的备用地址”
        // 最终通过签名恢复出签署者地址，用于后续权限校验
        // step 1: 将“激活备用地址”的关键信息打包，并通过哈希算法生成唯一的32字节哈希值（messageHash），确保数据不可篡改
        //  abi.encodePacked(): solidity中紧凑打包数据函数，将不同类型的参数按“无冗余”的方式拼接成二进制数据
        //  keccak256(): 区块链主流哈希算法，将一个二进制数据，计算成一个32字节固定长度的哈希值，为了达到防篡改和高效签名的目的
        bytes32 messageHash = keccak256(abi.encodePacked("ACTIVATE_BACKUP", targetUser, block.chainid));
        // step 2: 将哈希值（messageHash）按以太坊标准（EIP-191）处理成"可签名格式"，避免签名被误用于合约调用等场景。
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(messageHash);
        // step 3: 通过"以太坊标准签名哈希值"和"传入的签名"，反向推出签署者的地址
        address signer = ECDSA.recover(ethSignedMessageHash, partnerSignature);

        if(signer != target.mainKey) revert InvalidSignature();

        //激活备用钥匙
        address oldMainKey = target.mainKey;
        address oldBackupKey = target.backupKey;

        //将原备用钥匙替换为主钥匙，将原主钥匙替换为备用钥匙
        target.mainKey = oldBackupKey;
        target.backupKey = oldMainKey;

        emit BackupKeyActivated(targetUser, msg.sender, oldBackupKey);
    }

    /**
     * @dev 辅助函数：生成激活签名的消息值（messageHash），供前端使用
     * @param targetUser 要激活备用钥匙的用户
     * @return 消息值（messageHash）
     */
    function getActivationMessageHash(address targetUser) external view returns (bytes32){
        return keccak256(abi.encodePacked("ACTIVATE_BACKUP", targetUser, block.chainid));
    }

    /**
     * @dev 查看用户详情
     * @param user 用户地址
     * @return mainKey 主钥匙
     * @return backupKey 备用钥匙
     * @return isActive 是否激活
     * @return mutualPartner 绑定小伙伴
     */
    function getUserDetails(address user) external view returns(
        address mainKey,
        address backupKey,
        bool isActive,
        address mutualPartner
    ) {
        User storage u = users[user];
        return (u.mainKey, u.backupKey, u.isActive, u.mutualPartner);
    }

}
