using Microsoft.Ajax.Utilities;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using System.Web.Helpers;
using System.Web.Hosting;
using static System.Net.WebRequestMethods;
using File = System.IO.File;

namespace PhotosManager.Models
{
    public static class PhotosManagerDBEntities_ExtensionsMethods
    {
        const int SaltSize = 20;
        #region assets folders and default values
        const string AvatarsFolder = @"/Images_Data/Users_Avatars/";
        const string DefaultAvatar = @"no_avatar.png";

        const string PhotosFolder = @"/Images_Data/Photos/";
        const string DefaultPhoto = @"No_Image.png";
        #endregion
        #region Encryption
        private static string CreateSalt(int size)
        {
            RNGCryptoServiceProvider randomNumberGenerator = new RNGCryptoServiceProvider();
            byte[] buff = new byte[size];
            randomNumberGenerator.GetBytes(buff);
            return Convert.ToBase64String(buff); // web compatible format
        }
        private static string HashPassword(string password, string salt = "")
        {
            if (string.IsNullOrEmpty(salt)) salt = CreateSalt(SaltSize);
            string saltedPassword = password + salt;
            HashAlgorithm encryptAlgorithm = new SHA256CryptoServiceProvider();
            byte[] bytValue = System.Text.Encoding.UTF8.GetBytes(saltedPassword);
            byte[] bytHash = encryptAlgorithm.ComputeHash(bytValue);
            string base64 = Convert.ToBase64String(bytHash); // web compatible format
            return base64 + salt;
        }
        private static bool VerifyPassword(string password, string storedPassword)
        {
            string salt = storedPassword.Substring(storedPassword.Length - CreateSalt(SaltSize).Length);
            string hashedPassword = HashPassword(password, salt);
            return hashedPassword == storedPassword;
        }
        #endregion

        #region users CRUD
        public static void Clone(this User user, User copy)
        {
            user.Id = copy.Id;
            user.Avatar = copy.Avatar;
            user.Email = copy.Email;
            user.Password = copy.Password;
            user.Blocked = copy.Blocked;
            user.IsAdmin = copy.IsAdmin;
            user.Name = copy.Name;
        }
        public static void Update(this User user, User copy)
        {
            user.Id = copy.Id;
            user.Avatar = HandleAsset(copy.Avatar, user.Avatar, AvatarsFolder);
            user.Email = copy.Email;
            user.Password = !string.IsNullOrEmpty(copy.Password) ? copy.Password : HashPassword(user.Password);
            user.Blocked = copy.Blocked;
            user.IsAdmin = copy.IsAdmin;
            user.Name = copy.Name;
        }
        public static bool UserEmailExist(this PhotosManagerDBEntities DB, string email)
        {
            return DB.Users.Where(u => u.Email.ToLower() == email.ToLower()).FirstOrDefault() != null;
        }
        public static bool EmailConflict(this PhotosManagerDBEntities DB, string email)
        {
            User connectedUser = (User)HttpContext.Current.Session["ConnectedUser"];
            User foundUser = DB.Users.ToList().Where(u => u.Email == email).FirstOrDefault();
            if (foundUser != null)
                return foundUser.Id != connectedUser.Id;
            return false;
        }
        public static User NewUser(this PhotosManagerDBEntities DB)
        {
            return new User
            {
                Avatar = AvatarsFolder + DefaultAvatar
            };
        }
        public static User LogUser(this PhotosManagerDBEntities DB, LoginCredential credential)
        {
            User user = DB.Users.Where(u => u.Email == credential.Email).FirstOrDefault();
            if (user != null)
            {
                if (VerifyPassword(credential.Password, user.Password))
                    return user;
                else
                    return null;
            }
            return null;
        }

        public static User AddUser(this PhotosManagerDBEntities DB, User user)
        {
            if (user != null)
            {
                user.Password = HashPassword(user.Password);
                user.Avatar = HandleAsset(user.Avatar, "", AvatarsFolder);
                user = DB.Users.Add(user);
                DB.SaveChanges();
                return user;
            }
            return null;
        }
        public static User UpdateUser(this PhotosManagerDBEntities DB, User user)
        {
            if (user != null)
            {
                User storedUser = DB.Users.Find(user.Id);
                storedUser.Update(user);
                DB.Entry(storedUser).State = EntityState.Modified;
                DB.SaveChanges();
                user = DB.Users.Find(user.Id);
                return user;
            }
            return null;
        }
        public static bool DeleteUser(this PhotosManagerDBEntities DB, int id)
        {
            User user = DB.Users.Find(id);
            if (user != null)
            {
                BeginTransaction(DB);
                DB.Likes.RemoveRange(DB.Likes.Where(l => l.UserId == id));
                DeleteAssets(user.Avatar);
                DB.Users.Remove(user);
                DB.SaveChanges();
                Commit();
                return true;
            }
            return false;

        }
        public static void TooglePromoteUser(this PhotosManagerDBEntities DB, int id)
        {
            User user = DB.Users.Find(id);
            if (user != null)
            {
                user.IsAdmin = !user.IsAdmin;
                DB.Entry(user).State = EntityState.Modified;
                DB.SaveChanges();
            }
        }
        public static void ToogleBlockUser(this PhotosManagerDBEntities DB, int id)
        {
            User user = DB.Users.Find(id);
            if (user != null)
            {
                user.Blocked = !user.Blocked;
                DB.Entry(user).State = EntityState.Modified;
                DB.SaveChanges();
            }
        }
        #endregion

        #region photos CRUD
        public static void Update(this Photo photo, Photo copy)
        {
            photo.Id = copy.Id;
            photo.Image = HandleAsset(copy.Image, photo.Image, PhotosFolder);
            photo.Title = copy.Title;
            photo.Description = copy.Description;
            photo.OwnerId = copy.OwnerId;
            photo.Shared = copy.Shared;
            photo.CreationDate = DateTime.Now;
        }
        public static Photo NewPhoto(this PhotosManagerDBEntities DB)
        {
            return new Photo
            {
                Image = PhotosFolder + DefaultPhoto,
            };
        }
        public static Photo AddPhoto(this PhotosManagerDBEntities DB, Photo photo)
        {
            if (photo != null)
            {
                photo.CreationDate = DateTime.Now;
                photo.Image = HandleAsset(photo.Image, "", PhotosFolder);
                photo = DB.Photos.Add(photo);
                DB.SaveChanges();
                return photo;
            }
            return null;
        }
        public static Photo UpdatePhoto(this PhotosManagerDBEntities DB, Photo photo)
        {
            if (photo != null)
            {
                Photo storedPhoto = DB.Photos.Find(photo.Id);
                storedPhoto.Update(photo);
                DB.Entry(storedPhoto).State = EntityState.Modified;
                DB.SaveChanges();
                photo = DB.Photos.Find(photo.Id);
                return photo;
            }
            return null;
        }
        public static bool DeletePhoto(this PhotosManagerDBEntities DB, int id)
        {
            Photo photo = DB.Photos.Find(id);
            if (photo != null)
            {
                BeginTransaction(DB);
                DB.Likes.RemoveRange(DB.Likes.Where(l => l.PhotoId == id));
                DeleteAssets(photo.Image);
                DB.Photos.Remove(photo);
                DB.SaveChanges();
                Commit();
                return true;
            }
            return false;
        }
        #endregion

        #region Likes CRUD
        public static void ToogleLike(this PhotosManagerDBEntities DB, int photoId, int userId)
        {
            Like like = DB.Likes.Where(l => (l.PhotoId == photoId && l.UserId == userId)).FirstOrDefault();
            if (like != null)
                DB.Likes.Remove(like);
            else
                DB.Likes.Add(new Like { PhotoId = photoId, UserId = userId, CreationDate = DateTime.Now });
            DB.SaveChanges();
        }
        #endregion

        #region private methods
        private static string HandleAsset(string data, string previousDataUrl, string assetsFolder)
        {
            if (data != previousDataUrl)
            {
                if (!string.IsNullOrEmpty(data))
                {
                    if (!string.IsNullOrEmpty(previousDataUrl))
                    {
                        string assetToDeletePath = HostingEnvironment.MapPath(previousDataUrl);
                        if (File.Exists(assetToDeletePath)) File.Delete(assetToDeletePath);
                    }
                    string newAssetServerPath;
                    string[] base64Data = data.Split(',');
                    string extension = base64Data[0].Replace(";base64", "").Split('/')[1];
                    // MIME patch : IIS does not support webp and avif mimes
                    if ((extension.ToLower() == "webp") ||
                        (extension.ToLower() == "avif"))
                        extension = "png"; // png can embed webp and avif format

                    string assetData = base64Data[1];
                    string assetUrl;
                    do
                    {
                        var key = Guid.NewGuid().ToString();
                        assetUrl = assetsFolder + key + "." + extension;
                        newAssetServerPath = HostingEnvironment.MapPath(assetUrl);
                        // make sure new file does not already exists 
                    } while (File.Exists(newAssetServerPath));
                    var stream = new MemoryStream(Convert.FromBase64String(assetData));
                    FileStream file = new FileStream(newAssetServerPath, FileMode.Create, FileAccess.Write);
                    stream.WriteTo(file);
                    file.Close();
                    stream.Close();
                    return assetUrl;
                }
                return previousDataUrl;
            }
            else
                return previousDataUrl;
        }
        private static void DeleteAssets(string data)
        {
            if (!string.IsNullOrEmpty(data))
            {
                string assetToDeletePath = HostingEnvironment.MapPath(data).ToString();
                File.Delete(assetToDeletePath);
            }
        }
        private static DbContextTransaction Transaction
        {
            get
            {
                if (HttpContext.Current != null)
                {
                    return (DbContextTransaction)HttpContext.Current.Session["Transaction"];
                }
                return null;
            }
            set
            {
                if (HttpContext.Current != null)
                {
                    HttpContext.Current.Session["Transaction"] = value;
                }
            }
        }
        private static void BeginTransaction(PhotosManagerDBEntities DB)
        {
            if (Transaction != null)
                throw new Exception("Transaction en cours! Impossible d'en démarrer une nouvelle!");
            Transaction = DB.Database.BeginTransaction();
        }
        private static void Commit()
        {
            if (Transaction != null)
            {
                Transaction.Commit();
                Transaction.Dispose();
                Transaction = null;
            }
            else
                throw new Exception("Aucune transaction en cours! Impossible de mettre à jour la base de ddonnées!");
        }
        #endregion
    }
}