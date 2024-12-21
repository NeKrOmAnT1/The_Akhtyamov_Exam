using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace CardProcessor
{
    public class Card
    {
        public string Name { get; set; }
        public string Family { get; set; }
        public string CVC { get; set; }
        public string Month { get; set; }
        public string Year { get; set; }
        public string Number { get; set; }
    }

    public class CardData
    {
        public List<Card> Cards { get; set; }
    }

    public interface IHasher
    {
        string Hash(string input, string salt);
    }

    public class Md5Hasher : IHasher
    {
        public string Hash(string input, string salt)
        {
            using (var md5 = MD5.Create())
            {
                var saltedInput = input + salt;
                var hashBytes = md5.ComputeHash(Encoding.UTF8.GetBytes(saltedInput));
                return Convert.ToBase64String(hashBytes);
            }
        }
    }

    public interface IEncryptor
    {
        string Encrypt(string input, string key);
        string Decrypt(string input, string key);
    }

    public class AesEncryptor : IEncryptor
    {
        public string Encrypt(string input, string key)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key.PadRight(32));
                aes.IV = new byte[16];
                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    var inputBytes = Encoding.UTF8.GetBytes(input);
                    var encryptedBytes = encryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);
                    return Convert.ToBase64String(encryptedBytes);
                }
            }
        }

        public string Decrypt(string input, string key)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key.PadRight(32));
                aes.IV = new byte[16];
                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    var encryptedBytes = Convert.FromBase64String(input);
                    var decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
                    return Encoding.UTF8.GetString(decryptedBytes);
                }
            }
        }
    }

    public class CardProcessor
    {
        private readonly IHasher _hasher;
        private readonly IEncryptor _encryptor;
        private readonly string _salt;
        private readonly string _encryptionKey;

        public CardProcessor(IHasher hasher, IEncryptor encryptor, string salt, string encryptionKey)
        {
            _hasher = hasher;
            _encryptor = encryptor;
            _salt = salt;
            _encryptionKey = encryptionKey;
        }

        public void ProcessCards(string filePath)
        {
            var json = File.ReadAllText(filePath);
            var cardData = JsonConvert.DeserializeObject<CardData>(json);

            foreach (var card in cardData.Cards)
            {
                card.Number = _hasher.Hash(card.Number, _salt);
                card.CVC = _hasher.Hash(card.CVC, _salt);
                card.Name = _encryptor.Encrypt(card.Name, _encryptionKey);
                card.Family = _encryptor.Encrypt(card.Family, _encryptionKey);
                card.Month = _encryptor.Encrypt(card.Month, _encryptionKey);
                card.Year = _encryptor.Encrypt(card.Year, _encryptionKey);
            }

            var processedJson = JsonConvert.SerializeObject(cardData, Newtonsoft.Json.Formatting.Indented);
            File.WriteAllText(filePath.Replace(".json", "_processed.json"), processedJson);
        }
    }
    class Program
    {
        static void Main(string[] args)
        {
            string filePath = @"C:\Users\Pro\Downloads\Card (2).json";
            string salt = "MySecureSalt";
            string encryptionKey = "MySecretKey";

            var hasher = new Md5Hasher();
            var encryptor = new AesEncryptor();
            var processor = new CardProcessor(hasher, encryptor, salt, encryptionKey);

            processor.ProcessCards(filePath);
            Console.WriteLine("Обработка завершена. Данные сохранены в новый файл.");
        }
    }
}