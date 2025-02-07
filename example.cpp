#include "includes/preKeyBundle.h"
#include "includes/signal.h"
#include <iostream>
#include <string>
#include <vector>

int main() {
  using namespace SignalProtocol;

  // Create a Signal instance and register the user.
  Signal signalUser;
  signalUser.registerUser();

  // Get your PreKeyBundle for distribution.
  PreKeyBundle myBundle = signalUser.getPreKeyBundle();

  // Simulate obtaining a peer's PreKeyBundle (here we reuse our own for demo
  // purposes).
  PreKeyBundle peerBundle = myBundle;

  // Initiate a session with the peer.
  auto &session = signalUser.initiateSession("peer1", peerBundle);

  // Encrypt a message.
  std::string text = "Hello, Signal!";
  std::vector<uint8_t> plaintext(text.begin(), text.end());
  std::vector<uint8_t> ciphertext = signalUser.sendMessage("peer1", plaintext);

  // In a real scenario, the header would be transmitted with the ciphertext.
  // For demonstration, assume an empty header (not realistic).
  std::vector<uint8_t> header;
  std::vector<uint8_t> decrypted = session.decrypt(ciphertext, header);

  std::string decryptedText(decrypted.begin(), decrypted.end());
  std::cout << "Decrypted: " << decryptedText << std::endl;

  return 0;
}
