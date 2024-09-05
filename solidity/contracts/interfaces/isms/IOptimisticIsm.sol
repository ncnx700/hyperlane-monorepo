// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

import {IInterchainSecurityModule} from "../IInterchainSecurityModule.sol";

/**
 * @title IOptimisticIsm
 * @notice Performs optimistic verification of interchain messages in addition to verification via an alternative ISM.
 */
interface IOptimisticIsm is IInterchainSecurityModule {
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
    ) external;

    /**
     * @notice Returns packed IsmStatus struct for any ISM address
     * @param _submodule The ISM contract address
     * @return _fraudulentVotes The amount of watchers that have marked a submodule fraudulent
     * @return _voteThreshold The vote threshold at which a submodule is treated as fraudulent
     * @return _fraudWindow The optimistic fraud window (in seconds)
     */
    function ismStatus(
        address _submodule
    ) external view returns (uint64, uint64, uint40);

    /**
     * @notice Returns the address for the ISM submodule
     * @param _message Not used
     * @return _submodule The ISM contract address
     */
    function submodule(
        bytes calldata _message
    ) external view returns (IInterchainSecurityModule);

    /**
     * @notice Returns an array of watcher addresses
     * @return _watchers The array of watcher addresses
     */
    function watchers() external view returns (address[] memory);

    /**
     * @notice Adds an array of watcher addresses to the set of watchers
     * @param _newWatchers The array of watcher addresses
     */
    function addWatchers(address[] calldata _newWatchers) external;

    /**
     * @notice Removes an array of watcher addresses from the set of watchers
     * @param _removedWatchers The array of watcher addresses
     */
    function removeWatchers(address[] calldata _removedWatchers) external;

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
    ) external;

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
    ) external returns (bool);

    /**
     * @notice Used by watchers to mark a submodule ISM as fraudulent
     * @dev Watchers are only allowed to mark a submodule ISM as fraudulent once, and it's irrevocable
     * @param _submodule The ISM contract address
     */
    function markFraudulent(address _submodule) external;
}
