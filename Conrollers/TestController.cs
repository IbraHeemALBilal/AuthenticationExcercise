using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationExcercise.Conrollers
{
    [Route("api/test")]
    [Authorize]
    [ApiController]
    public class TestController : ControllerBase
    {
        [HttpGet("hellow")]
        public IActionResult PrintHellow()
        {
            return Ok("Hellow World !");
        }
    }
}
