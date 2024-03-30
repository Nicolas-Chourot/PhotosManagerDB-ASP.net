using PhotosManager.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace PhotosManager.Controllers
{
    public class AccountsController : Controller
    {
        private readonly PhotosManagerDBEntities DB = new PhotosManagerDBEntities();

        public JsonResult EmailExist(string Email)
        {
            bool exist = DB.UserEmailExist(Email);
            return Json(exist, JsonRequestBehavior.AllowGet);
        }
        [UserAccess]
        public JsonResult EmailConflict(string Email)
        {
            bool conflict = DB.EmailConflict(Email);
            return Json(conflict, JsonRequestBehavior.AllowGet);
        }
        public ActionResult ExpiredSession()
        {
            return Redirect("/Accounts/Login?message=Session expirée, veuillez vous reconnecter.");
        }
        public ActionResult Logout()
        {
            return RedirectToAction("Login", "Accounts");
        }
        
        public ActionResult Login(string message = "")
        {
            Session["LoginMessage"] = message;
            if (Session["currentLoginEmail"] == null) Session["currentLoginEmail"] = "";
            Session["connectedUser"] = null;
            return View();
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(LoginCredential credential)
        {
            credential.Email = credential.Email.Trim();
            credential.Password = credential.Password.Trim();
            Session["currentLoginEmail"] = credential.Email;
            Session["connectedUser"] = DB.LogUser(credential);
            if (Session["connectedUser"] == null)
            {
                Session["LoginMessage"] = "Erreur de connexion!";
                return View();
            }
            else
            {
                User user = (User)Session["connectedUser"];
                if (user.Blocked)
                {
                    return Redirect("/Accounts/Login?message=Votre compte a été bloqué!");
                }
            }
            return RedirectToAction("List", "Photos");
        }
        public ActionResult Subscribe()
        {
            Session["connectedUser"] = null;
            Session["currentLoginEmail"] = "";
            return View(new User());
        }
        [HttpPost]
        [ValidateAntiForgeryToken()]
        public ActionResult Subscribe(User user)
        {
            DB.AddUser(user);
            return Redirect("/Accounts/Login?message=Création de compte effectué avec succès!");
        }
        [UserAccess]
        public ActionResult EditProfil()
        {
            User connectedUser = (User)Session["connectedUser"];
            if (connectedUser != null)
            {
                return View(connectedUser);
            }
            return RedirectToAction("Login", "Accounts");
        }
        [UserAccess]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult EditProfil(User user)
        {
            User connectedUser = (User)Session["connectedUser"];
            // far more secure than than retreive the following value from the form data
            user.Id = connectedUser.Id;
            user.Blocked = false;
            user.IsAdmin = connectedUser.IsAdmin;
            Session["connectedUser"] = DB.UpdateUser(user);
            return RedirectToAction("List", "Photos");
        }
        [UserAccess]
        public ActionResult DeleteProfil()
        {
            User connectedUser = (User)Session["ConnectedUser"];
            DB.DeleteUser(connectedUser.Id);
            return Redirect("Login?message=Votre compte a été effacé avec succès!");
        }
        [AdminAccess]
        public ActionResult ManageUsers()
        {
            return View(DB.Users.ToList().OrderBy(u => u.Name).ToList());
        }
        [AdminAccess]
        public ActionResult TooglePromoteUser(int id)
        {
            DB.TooglePromoteUser(id);
            return RedirectToAction("ManageUsers");
        }
        [AdminAccess]
        public ActionResult ToogleBlockUser(int id)
        {
            DB.ToogleBlockUser(id);
            return RedirectToAction("ManageUsers");
        }
        [AdminAccess]
        public ActionResult DeleteUser(int id)
        {
            DB.DeleteUser(id);
            return RedirectToAction("ManageUsers");
        }
    }
}