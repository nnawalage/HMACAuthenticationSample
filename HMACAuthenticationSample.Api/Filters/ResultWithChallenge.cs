using System.Configuration;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;

namespace HMACAuthenticationSample.Api.Filters
{
    public class ResultWithChallenge : IHttpActionResult
    {
        private readonly IHttpActionResult next;

        public ResultWithChallenge(IHttpActionResult next)
        {
            this.next = next;
        }

        public async Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            var response = await next.ExecuteAsync(cancellationToken);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                string authenticationScheme = ConfigurationManager.AppSettings["authenticationScheme"];
                response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue(authenticationScheme));
            }

            return response;
        }
    }
}