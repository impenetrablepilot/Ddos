// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title DDoS Mitigation Contract
/// @notice Reference Solidity contract mirroring smart_contract.py.
///         Deployable on a local Ethereum test network (Ganache/Hardhat)
///         for anyone extending this project to a real blockchain.
///         The off-chain ML detector calls submitDetection(); this
///         contract deterministically decides the mitigation action and
///         emits an event that becomes part of the chain's permanent log.
contract DDoSMitigation {
    enum Action { ALLOW, MONITOR, RATE_LIMIT, CHALLENGE, BLACKLIST }

    struct Detection {
        string sourceId;
        string predictedLabel;
        uint8 confidencePct; // 0-100
        Action action;
        uint256 timestamp;
    }

    address public owner;
    uint8 public constant CONFIDENCE_THRESHOLD = 60;
    uint8 public constant REPEAT_OFFENSE_THRESHOLD = 2;

    mapping(string => uint256) public strikes;      // sourceId -> strike count
    mapping(string => bool) public blacklisted;      // sourceId -> blacklisted?
    Detection[] public detectionLog;

    event MitigationTriggered(
        string sourceId,
        string predictedLabel,
        uint8 confidencePct,
        Action action,
        uint256 timestamp
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Only the contract owner may call this");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Called by the off-chain ML detection service for every
    ///         flow classified as non-benign (benign traffic need not
    ///         be submitted on-chain, to save gas).
    function submitDetection(
        string calldata sourceId,
        string calldata predictedLabel,
        uint8 confidencePct
    ) external onlyOwner returns (Action) {
        Action action;

        if (confidencePct < CONFIDENCE_THRESHOLD) {
            action = Action.MONITOR;
        } else {
            strikes[sourceId] += 1;

            if (strikes[sourceId] >= REPEAT_OFFENSE_THRESHOLD) {
                action = Action.BLACKLIST;
                blacklisted[sourceId] = true;
            } else if (
                keccak256(bytes(predictedLabel)) == keccak256(bytes("syn_flood")) ||
                keccak256(bytes(predictedLabel)) == keccak256(bytes("udp_flood"))
            ) {
                action = Action.RATE_LIMIT;
            } else if (keccak256(bytes(predictedLabel)) == keccak256(bytes("http_flood"))) {
                action = Action.CHALLENGE;
            } else {
                action = Action.MONITOR;
            }
        }

        detectionLog.push(Detection(sourceId, predictedLabel, confidencePct, action, block.timestamp));
        emit MitigationTriggered(sourceId, predictedLabel, confidencePct, action, block.timestamp);
        return action;
    }

    function detectionCount() external view returns (uint256) {
        return detectionLog.length;
    }

    function isBlacklisted(string calldata sourceId) external view returns (bool) {
        return blacklisted[sourceId];
    }
}
