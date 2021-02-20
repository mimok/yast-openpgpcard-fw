# OpenPGP Card firmware for YAST

## Purpose of this firmware
This firmware implements the OpenPGP Card standard version 3.4. The following features are available:

- RSA 2048 keys (up to 4096 by modifying
- 6 digit PW1 password, 8 digit PW3 and RC passwords
- Get challenge (upto 3070 bytes per call)
- Factory reset
- Key generation and key import

The token harware and firmware are specifically designed to prevent the usage of the keys without the consent of the user. Keys stored onto the token cannot be extracted by any means.

## Disclaimer
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, 
BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, 
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, 
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Security problem
### Threats
The following threat has been considered during the development of the application:

- After the token has been lost or stolen, an attacker tries to use the credetials and keys stored on it.

### Attacker
The attacker has a physical access to the token and is able to fully unlock the LPC55Sxx chip to execute its own code (even though there is, as far as i know, no known attack against this particular chip yet).

### Hypothesis
We are considering that the following hypothesis apply:

- Once unlocked, the legitimate user of the token does not leave it alone plugged onto a computer. Indeed, once unlocked any person whith a physical access to the token would be able to use it (but you can enable PIN check before each signature operation).
- The legitimate user of the token do not plug it on a compromised computer. Indeed, once unlocked a compromised computer could theoritically intercept the user PIN code, tamper with the executed commands or even tamper with the data which will be signed by the key.
- The legitimate user do not use the token anymore if the token is found after being lost. Indeed, considering that the LPC55Sxx firmware might be compromised, the token cannot be trusted anymore.

### Implemented security functions
The security of the Open PGP application fully relies on the security of the SE05x secure element. Almost all security operations are delegated to this component (PIN check, cryptographic operation, key manipulation and sensitive data storage) except the following ones:

- User can force the PIN to be entered before each signature operation. This security feature is actually enforced by LPC55Sxx firmware. PW1 PIN session on SE05x is not actually closed as it would prevent the user from using other features (decryption or internal authentication) without having to enter the PIN again.
- PIN update. SE05x does not implement atomic update of PIN objects, a power loss occuring during a PIN update could put the token in an inappropriate state (i.e. without any PIN object to protect the usage of token assets). Hence, LPC55Sxx locks the SE05x chip before each PIN update using the new PIN code and unlock it at the end of the process. If a power loss occurs, the SE05x remains locked and the user will have to unlock it using the new PIN. At the end of the recovery process the actual PIN of the token is either the old PIN (if power loss occurs before old PIN erasing) or the new PIN (if power loss occurs after old PIN erasing) just like if the PIN update operation was atomic.

## Cloning and compiling
To compile this software, you will need MCUXpresso IDE v11.30.0_5222 and SDK 2.9.0.
To import the project click on File > Import... > Git > Project from Git > Clone URI.
The in the *Source Git Repository* windows entre the URL of the Github repository.
Follow the instructions and the repo should be cloned localy and imported into MCUXpresso.
Finally, use MCUXpresso to compile the projet.

Two build configurations are available:

- Debug: Debug symbols + logs
- Release: Optimized code whithout logs and debug symbols.

## Porting on official LPC55S28 development kit from NXP
This code can be executed on the LPC55S28 dev. kit from NXP, you will need the following piece of hardware:

- [LPC55S28 dev. kit](https://www.nxp.com/design/software/development-software/lpcxpresso55s28-development-board:LPC55S28-EVK)
- [SE050 dev. kit](https://www.nxp.com/products/security-and-authentication/authentication/edgelock-se050-development-kit:OM-SE050X)

You will have to switch the I2C port from I2C1 to I2C4 in fil i2c_lpc55sxx.c.
You may have to lower the I2C baudrate from (1700U * 1000) to (400U * 1000U).

## License
Most of code is licensed under BSD-3 clause au Apache 2.0 license
See license file and file headears for more information.