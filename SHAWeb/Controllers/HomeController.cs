using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using SHAWeb.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using System.Text;
using System.Security.Cryptography;
using SHA256Alog;

namespace SHAWeb.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult About()
        {
            return View();
        }

        public ActionResult Create()
        {
            return View();
        }


        [HttpPost]
        public IActionResult Index(msg mesg)
        {
            string name;
            name = mesg.name;


            if (mesg.cry == "Hash")
            {

                String MessageYouWantToEncrypt = name;
                Message Key = new Message(MessageYouWantToEncrypt);
                string hash = String.Empty;
                // Initialize a SHA256 hash object
                using (SHA256 sha256 = SHA256.Create())
                {
                    // Compute the hash of the given string
                    byte[] hashValue = sha256.ComputeHash(Encoding.UTF8.GetBytes(MessageYouWantToEncrypt));

                    // Convert the byte array to string format
                    foreach (byte b in hashValue)
                    {
                        hash += $"{b:X2}";
                    }
                }
                if (hash == Key.EncryptedMessage)
                {
                    mesg.res = Key.EncryptedMessage;
                }
                else mesg.res = "Not Generated :(";
            }
            ViewData["res"] = mesg.res;

            return View();
        }

       
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
