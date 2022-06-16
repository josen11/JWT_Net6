namespace JWT_Net6
{
    public class User
    {
        public string UserName { get; set; } =  string.Empty;
        public byte[] PasswordHash { get; set; }
        public byte[] PasswordSalt { get; set; }

    }
}
