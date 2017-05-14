using System.Net;
using Microsoft.Bot.Connector;
using Newtonsoft.Json;

public static async Task<Activity> Run(HttpRequestMessage req, TraceWriter log)
{
    string content = await req.Content.ReadAsStringAsync();

    var input = JsonConvert.DeserializeObject<Activity>(content);
    var sampleResponseActivity = Activity.CreateMessageActivity();
    sampleResponseActivity.Text = "Here's your response: " + input.From.Name + " you wrote: " + input.Text;


    return (Activity)sampleResponseActivity;
}