using HMACAuthenticationSample.Api.Filters;
using HMACAuthenticationSample.Api.Models;
using System.Web.Http;

namespace HMACAuthenticationSample.Api.Controllers
{
    [HmacAuthentication]
    public class ItemController : ApiController
    {
        [HttpGet]
        public IHttpActionResult Get()
        {
            return Ok(new Item() { Id=1, Name="TestGetItem"});
        }


        [HttpPost]
        public IHttpActionResult Post (Item item) 
        {
            return Ok(item);
        }
    }
}
