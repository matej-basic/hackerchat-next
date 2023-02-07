import GetWebSocket from "./GetWebSocket";

async function GetUserList() {
    const socket = GetWebSocket()
    var userArray;
    var usersString;
    var arrayOfUsers;
    // @ts-ignore
    var returnValue = []

    if (socket != null) {
        socket.onopen = function (ev) {
            socket.send("GET USERLIST")
        }
        socket.onmessage = function (ev) {
            if (ev.data != null) {
                if ((/^USERS---/.test(ev.data.toString()))) {
                    userArray = ev.data.toString().split('---')
                    userArray.splice(0, 1)
                    userArray[0] = userArray[0].split("[")[1]
                    userArray[userArray.length - 1] = userArray[userArray.length - 1].split("]")[0]
                    usersString = userArray.toString()
                    arrayOfUsers = usersString.split(",")
                    Object.values(arrayOfUsers).map(user => {
                        // @ts-ignore
                        var jsonUser = JSON.parse(user)
                        returnValue.push(jsonUser.username)
                    })
                }
            }
        }
    }

    // @ts-ignore
    return returnValue
}

export default GetUserList