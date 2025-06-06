// This file is part of Rundler.
//
// Rundler is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later version.
//
// Rundler is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Rundler.
// If not, see https://www.gnu.org/licenses/.

use alloy_sol_macro::sol;

sol!(
    #[allow(missing_docs)]
    #[derive(Default, Debug, PartialEq, Eq)]
    library EstimationTypes {
        error EstimateGasResult(uint256 gas, uint256 numRounds);

        error EstimateGasContinuation(uint256 minGas, uint256 maxGas, uint256 numRounds);

        error EstimateGasRevertAtMax(bytes revertData);

        error TestCallGasResult(bool success, uint256 gasUsed, bytes revertData);
    }
);
