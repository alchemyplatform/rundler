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

//! Least-squares line fit, used to split bundle overhead into shared and per-op terms and
//! calldata cost into fixed and per-byte terms.

use serde::Serialize;

/// `y = intercept + slope * x`
#[derive(Debug, Clone, Serialize)]
pub struct LineFit {
    pub intercept: f64,
    pub slope: f64,
    /// Largest absolute distance of a point from the line. Near zero means the model is exact.
    pub max_abs_residual: f64,
    pub points: usize,
}

/// Fits a line through `(x, y)` points. Returns `None` for fewer than two distinct `x`.
pub fn line(points: &[(f64, f64)]) -> Option<LineFit> {
    let n = points.len() as f64;
    let mean_x = points.iter().map(|p| p.0).sum::<f64>() / n;
    let mean_y = points.iter().map(|p| p.1).sum::<f64>() / n;
    let sxx: f64 = points.iter().map(|p| (p.0 - mean_x).powi(2)).sum();
    if points.len() < 2 || sxx == 0.0 {
        return None;
    }
    let sxy: f64 = points.iter().map(|p| (p.0 - mean_x) * (p.1 - mean_y)).sum();
    let slope = sxy / sxx;
    let intercept = mean_y - slope * mean_x;
    let max_abs_residual = points
        .iter()
        .map(|p| (p.1 - (intercept + slope * p.0)).abs())
        .fold(0.0, f64::max);
    Some(LineFit {
        intercept,
        slope,
        max_abs_residual,
        points: points.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_line() {
        let fit = line(&[(1.0, 21_500.0), (2.0, 22_000.0), (5.0, 23_500.0)]).unwrap();
        assert!((fit.slope - 500.0).abs() < 1e-9);
        assert!((fit.intercept - 21_000.0).abs() < 1e-9);
        assert!(fit.max_abs_residual < 1e-9);
    }

    #[test]
    fn degenerate() {
        assert!(line(&[(1.0, 1.0)]).is_none());
        assert!(line(&[(1.0, 1.0), (1.0, 2.0)]).is_none());
    }
}
