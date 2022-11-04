#include <iostream>
#include <helib/helib.h>
#include <helib/Context.h>
// using namespace std;


// Plaintext prime modulus
unsigned long p = 4999;
unsigned long p_small = 17;
// Cyclotomic polynomial - defines phi(m)
unsigned long m = 130;
// Hensel lifting (default = 1)
unsigned long r = 1;
// Number of bits of the modulus chain
unsigned long bits = 500;
// Number of columns of Key-Switching matrix (default = 2 or 3)
unsigned long c = 2;


// Initialize context
// This object wiint hold information about the algebra created from the
// previously set parameters

// Print the security level
// std::cout << "Security: " << query_context.securityLevel() << std::endl;

// Secret key management
// std::cout << "Creating secret key..." << std::endl;
// Create a secret key associated with the context
// Generate the secret key

void modulars_down(helib::Ctxt &ctxt) {
  ctxt.reducePtxtSpace(13);
}



// helib::Ptxt<helib::BGV> init_query() {
//   // query context that is to compare with
  

//   // Create a vector of long with nslots elements
//   helib::Ptxt<helib::BGV> ptxt(context);
//   // Set it with numbers 0..nslots - 1
//   // ptxt = [0] [1] [2] ... [nslots-2] [nslots-1]
//   for (int i = 0; i < ptxt.size(); ++i) {
//     if (i%2 == 0) {
//       ptxt[i] = i;
//     } else {
//       ptxt[i] = 2 + i;
//     }
//   }

//   // Print the plaintext
//   std::cout << "Initial Query Plaintext: " << ptxt << std::endl;


//   return ptxt;
// }

int main(){
  // helib::Ptxt pqtxt = init_query();

  std::cout << "before construct context." << std::endl;
  helib::Context context = helib::ContextBuilder<helib::BGV>()
                              .m(m)
                              .p(p)
                              .r(r)
                              .bits(bits)
                              .c(c)
                              .build();

  helib::Context context_small = helib::ContextBuilder<helib::BGV>()
                              .m(m)
                              .p(p_small)
                              .r(r)
                              .bits(bits)
                              .c(c)
                              .build();

  std::cout << "after construct context." << std::endl;
  helib::Ptxt<helib::BGV> ptxt(context);
  helib::Ptxt<helib::BGV> ptxt_small(context_small);

  for (int i = 0; i < ptxt.size(); ++i) {
    ptxt[i] = i;
  }


  for (int i = 0; i < ptxt.size(); ++i) {
    ptxt_small[i] = 0;
  }

  // Print the plaintext
  std::cout << "Initial Plaintext: " << ptxt << std::endl;


  helib::SecKey secret_key(context);
  helib::SecKey secret_key_small(context_small);

  secret_key.GenSecKey();
  secret_key_small.GenSecKey();
  // std::cout << "Generating key-switching matrices..." << std::endl;
  // Compute key-switching matrices that we need
  helib::addSome1DMatrices(secret_key);
  helib::addSome1DMatrices(secret_key_small);

  std::cout << "after Plaintext: " << ptxt << std::endl;
  // Public key management
  // Set the secret key (upcast: SecKey is a subclass of PubKey)
  helib::PubKey& public_key = secret_key;
  helib::PubKey& public_key_small = secret_key_small;

  // Get the EncryptedArray of the context
  const helib::EncryptedArray& ea = context.getEA();

  // Get the number of slot (phi(m))
  long nslots = ea.size();
  std::cout << "Number of slots: " << nslots << std::endl;

  // Create a ciphertext object
  helib::Ctxt ctxt(public_key);
  helib::Ctxt ctxt_small(public_key_small);
  // Encrypt the plaintext using the public_key

  public_key.Encrypt(ctxt, ptxt);
  public_key.Encrypt(ctxt_small, ptxt_small);

  // helib::Ctxt cqtxt(public_key);
  // public_key.Encrypt(cqtxt, pqtxt);

  // ctxt.reducePtxtSpace(p_small);
  // cqtxt -= ctxt;

  ctxt += ctxt_small;

  // std::cout << "goning to do power with p_small = " << p_small << std::endl;

  // ctxt.power(p_small - 1);
  

  // Decrypt the modified ciphertext into a new plaintext
  helib::Ptxt<helib::BGV> p_smalllaintext_result(context);
  secret_key.Decrypt(p_smalllaintext_result, ctxt);


  std::cout << "Decrypted Result: " << p_smalllaintext_result << std::endl;

  return 0;


}
