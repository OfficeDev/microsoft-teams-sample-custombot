#load "auth.csx"

using System.Net;
using Microsoft.Bot.Connector;
using Newtonsoft.Json;

public static async Task<Activity> Run(HttpRequestMessage req, TraceWriter log)
{
    string content = await req.Content.ReadAsStringAsync();

    var input = JsonConvert.DeserializeObject<Activity>(content);
    var sampleResponseActivity = Activity.CreateMessageActivity();
    AuthResponse authResponse = await AuthProvider.Validate(req);

    if (authResponse.AuthSuccessful)
    {
        sampleResponseActivity.Text = "Here's your response: " + input.From.Name + " you wrote: " + input.Text;
    }
    else
    {
        sampleResponseActivity.Text = authResponse.ErrorMessage;
    }


    return (Activity)sampleResponseActivity;
}