json = require "json"

done = function(summary, latency, requests)
    io.write(json.encode({ json_report = summary }))
end
