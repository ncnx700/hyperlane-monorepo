// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

// ============ External Imports ============
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

// ============ Internal Imports ============
// NOTE: Only needed if routing between multiple submodule ISMs is necessary
//import {Message} from "../../libs/Message.sol";
import {IOptimisticIsm} from "../../interfaces/isms/IOptimisticIsm.sol";
import {IInterchainSecurityModule} from "../../interfaces/IInterchainSecurityModule.sol";

/**
 * @title OptimisticIsm
 * @notice Performs optimistic verification of interchain messages in addition to verification via an alternative ISM.
 */
contract OptimisticIsm is IOptimisticIsm, OwnableUpgradeable {
    // NOTE: Only needed if routing between multiple submodule ISMs is necessary
    //using Message for bytes;
    using Address for address;
    using EnumerableSet for EnumerableSet.AddressSet;

    // ============ Errors ============

    /// @notice Fraud window hasn't elapsed
    error FraudWindow();
    /// @notice Zero address provided to function
    error ZeroAddress();
    /// @notice Submodule ISM address is not a deployed contract
    error NotContract();
    /// @notice Caller isn't a watcher
    error Unauthorized();
    /// @notice Submodule ISM already marked as fraudulent by watcher
    error AlreadyMarked();
    /// @notice Submodule ISM marked as fraudulent by a minimum threshold of watchers
    error FraudulentIsm();
    /// @notice Interchain message not preverified
    error NotPreverified();
    /// @notice Interchain message already verified
    error AlreadyVerified();
    /// @notice Interchain message already preverified
    error AlreadyPreverified();

    // ============ Structs ============

    /// @notice Used to pack information about the submodule ISM
    struct IsmStatus {
        uint64 fraudulentVotes;
        uint64 voteThreshold;
        uint40 fraudWindow;
    }

    // ============ Constants ============

    /// @notice Defines this ISM's type
    /// @dev The ROUTING type is used as this ISM defers initial verification to a submodule
    // solhint-disable-next-line const-name-snakecase
    uint8 public constant moduleType =
        uint8(IInterchainSecurityModule.Types.ROUTING);

    // ============ Mutable Storage ============

    /// @notice Returns packed IsmStatus struct for any ISM address
    mapping(address ism => IsmStatus) public ismStatus;
    /// @notice Returns verification timestamp using an interchain message's keccak256 hash
    mapping(bytes32 messageHash => uint256 timestamp) private _verification;
    /// @notice Returns a watcher's fraudulent vote status for a given ISM address
    mapping(address watcher => mapping(address ism => bool))
        private _watcherVotes;
    /// @notice Contains the set of watchers
    /// NOTE: Everything utilizing this can be optimized by replacing watcher authorization with an address => bool mapping if storing them all isn't necessary
    EnumerableSet.AddressSet private _watchers;
    /// @notice The interface for the submodule ISM
    IInterchainSecurityModule private _ism;

    // ============ Initializer ============

    /**
     * @notice Initializes the OptimisticIsm
     * @dev _owner cannot be the zero address, and _submodule must be a deployed contract
     * @param _owner Contract owner
     * @param _submodule ISM used for message verification
     * @param _voteThreshold Vote threshold required to mark submodule ISM as fraudulent
     * @param _fraudWindow The duration of the optimistic fraud window (in seconds)
     */
    function initialize(
        address _owner,
        address _submodule,
        uint64 _voteThreshold,
        uint40 _fraudWindow
    ) external initializer {
        if (_owner == address(0)) revert ZeroAddress();
        if (!_submodule.isContract()) revert NotContract();
        __Ownable_init();
        _transferOwnership(_owner);
        _ism = IInterchainSecurityModule(_submodule);
        ismStatus[_submodule] = IsmStatus({
            fraudulentVotes: 0,
            voteThreshold: _voteThreshold,
            fraudWindow: _fraudWindow
        });
    }

    // ============ View Functions ============

    /**
     * @notice Returns the address for the ISM submodule
     * @param _message Not used
     * @return _submodule The ISM contract address
     */
    // NOTE: How am I supposed to route between submodules? No instructions for how to handle _message were provided
    function submodule(
        bytes calldata _message
    ) external view returns (IInterchainSecurityModule) {
        return _ism;
    }

    /**
     * @notice Returns an array of watcher addresses
     * @return _watchers The array of watcher addresses
     */
    function watchers() external view returns (address[] memory) {
        return _watchers.values();
    }

    // ============ Owner Functions ============

    /**
     * @notice Adds an array of watcher addresses to the set of watchers
     * @param _newWatchers The array of watcher addresses
     */
    function addWatchers(address[] calldata _newWatchers) external onlyOwner {
        for (uint256 i; i < _newWatchers.length; ) {
            _watchers.add(_newWatchers[i]);
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Removes an array of watcher addresses from the set of watchers
     * @param _removedWatchers The array of watcher addresses
     */
    function removeWatchers(
        address[] calldata _removedWatchers
    ) external onlyOwner {
        for (uint256 i; i < _removedWatchers.length; ) {
            _watchers.remove(_removedWatchers[i]);
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Configures the submodule address, fraudulent vote threshold, and/or fraud window
     * @dev _submodule must be a deployed contract, provide the existing ISM address to reconfigure the vote threshold and fraud window
     * Submodules marked fraudulent must be replaced or have their threshold increased
     * @param _submodule The ISM contract address
     * @param _voteThreshold The fraudulent vote threshold
     * @param _fraudWindow The optimistic fraud window (in seconds)
     */
    function configureSubmodule(
        address _submodule,
        uint64 _voteThreshold,
        uint40 _fraudWindow
    ) external onlyOwner {
        if (!_submodule.isContract()) revert NotContract();

        _ism = IInterchainSecurityModule(_submodule);
        ismStatus[_submodule] = IsmStatus({
            fraudulentVotes: ismStatus[_submodule].fraudulentVotes,
            voteThreshold: _voteThreshold,
            fraudWindow: _fraudWindow
        });
    }

    // ============ Relayer Functions ============

    /**
     * @notice Preverifies an interchain message using the configurable ISM submodule
     * @dev A message cannot be preverified after successful preverification, and this will revert if the submodule ISM is marked as fraudulent
     * @param _metadata The relayer metadata utilized during the verifying ISM
     * @param _message The interchain message being verified
     * @return _success The preverification status
     */
    function preVerify(
        bytes calldata _metadata,
        bytes calldata _message
    ) external returns (bool) {
        bytes32 messageHash = keccak256(_message);
        if (_verification[messageHash] > 0) revert AlreadyPreverified();

        IsmStatus memory _ismStatus = ismStatus[address(_ism)];
        if (_ismStatus.fraudulentVotes > _ismStatus.voteThreshold)
            revert FraudulentIsm();

        bool success = _ism.verify(_metadata, _message);
        if (success) _verification[messageHash] = block.timestamp;
        return success;
    }

    /**
     * @notice Used by watchers to mark a submodule ISM as fraudulent
     * @dev Watchers are only allowed to mark a submodule ISM as fraudulent once, and it's irrevocable
     * @param _submodule The ISM contract address
     */
    function markFraudulent(address _submodule) external {
        if (!_watchers.contains(msg.sender)) revert Unauthorized();
        if (_watcherVotes[msg.sender][_submodule]) revert AlreadyMarked();
        _watcherVotes[msg.sender][_submodule] = true;
        unchecked {
            ++ismStatus[_submodule].fraudulentVotes;
        }
    }

    /**
     * @notice Verifies an interchain message was preverified by a valid submodule ISM and the fraud window has elapsed
     * @dev Will revert if the submodule ISM was marked as fraudulent, if the message wasn't preverified, if it was already verified, or if the fraud window hasn't elapsed
     * @param _metadata Not used
     * @param _message The interchain message being verified
     */
    function verify(
        bytes calldata _metadata,
        bytes calldata _message
    ) external returns (bool) {
        IsmStatus memory _ismStatus = ismStatus[address(_ism)];
        if (_ismStatus.fraudulentVotes > _ismStatus.voteThreshold)
            revert FraudulentIsm();

        bytes32 messageHash = keccak256(_message);
        uint256 verification = _verification[messageHash];
        if (verification == 0) revert NotPreverified();
        if (verification == type(uint256).max) revert AlreadyVerified();
        if (verification < block.timestamp - 7 days) revert FraudWindow();

        _verification[messageHash] = type(uint256).max;
        return true;
    }
}
