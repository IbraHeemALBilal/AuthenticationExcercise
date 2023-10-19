namespace AuthenticationExcercise
{
    public class User
    {
        public int UserId { get; set; }
        public string UserName { get; set; }
        public string Name { get; set; }
        public string City { get; set; }
        public string Password { get; set; }

        
        public User(int userId, string userName, string name, string city, string password)
        {
            UserId = userId;
            UserName = userName;
            Name = name;
            City = city;
            Password = password;
        }
    }
}
