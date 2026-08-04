[ApiController]
[Route("api/probe")]
public sealed class ProbeController : ControllerBase
{
    [HttpGet("reachability")]
    public async Task<ActionResult<string>> CheckReachability(
        [FromQuery] string host,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return BadRequest();
        }

        var result = await ReachabilityChecker.ProbeAsync(host, cancellationToken).ConfigureAwait(false);
        return Ok(result);
    }

    // SAFE: passes a value it computed itself, not one bound from the request.
    [HttpGet("selftest")]
    public async Task<ActionResult<string>> SelfTest(CancellationToken cancellationToken)
    {
        var result = await ReachabilityChecker.ProbeAsync("127.0.0.1", cancellationToken).ConfigureAwait(false);
        return Ok(result);
    }
}
