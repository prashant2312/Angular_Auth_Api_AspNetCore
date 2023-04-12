using System.Security.Cryptography;

namespace Angular_Auth_Api.Helpers
{
    public class Passwordhasher
    {
        private static RandomNumberGenerator rng=RandomNumberGenerator.Create();
        private static readonly int Saltsize = 16;
        private static readonly int HashSize = 20;
        private static readonly int Iterations = 10000;

        public static string HashPassword(string password)
        {
            byte[] salt;
            rng.GetBytes(salt=new byte[Saltsize]);
            var key=new Rfc2898DeriveBytes(password,salt,Iterations);
            var hash = key.GetBytes(HashSize);

            var hashbyte = new byte[Saltsize + HashSize];
            Array.Copy(salt,0, hashbyte,0,Saltsize);
            Array.Copy(hash,0,hashbyte,Saltsize,HashSize);

            var base64Hash=Convert.ToBase64String(hashbyte);

            return base64Hash;
        }
        public static bool VerifyPassword(string password,string base64Hash) 
        {
            var hashBytes=Convert.FromBase64String(base64Hash);

            var salt=new byte[Saltsize];
            Array.Copy(hashBytes,0,salt,0,Saltsize);  
            var key=new Rfc2898DeriveBytes(password,salt,Iterations);
            byte[] hash=key.GetBytes(HashSize);
            for (int i = 0; i < HashSize; i++)
            {
                if (hashBytes[i + Saltsize] != hash[i]) 
                {
                    return false;
                }
            }
            return true;
        }
    }
}
