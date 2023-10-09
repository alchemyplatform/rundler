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

use enr::{k256::ecdsa::SigningKey, Enr};
type DefaultEnr = Enr<SigningKey>;

const ENR: &str = "enr:-KS4QCQ532T4aeH41TZSa_FrI6zg0Jf9WpiZ1Rw132AOnaq1TOXR_39a_waEPSKnO3KtDUDm7ZyuWoPck98muyJfoFYFgmlkgnY0gmlwhCOy3eCPbWVtcG9vbF9zdWJuZXRziAAAAAAAAAAAiXNlY3AyNTZrMaEDqEoI-drfPYvv-nb7T2cPA_g18xcEijBBdlW4tZ8sZteDdGNwghDxg3VkcIIQ8Q";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let decoded_enr: DefaultEnr = ENR.parse().unwrap();
    println!("ENR: {:?}", decoded_enr);
    Ok(())
}
