let logout = document.getElementById("div-log-out-window");
let logoutButton = document.getElementById("logout-btn");
let leaveLogOut = document.getElementById("leaveLogOut");
let buttonLogOut = document.getElementById("buttonLogOut");

logoutButton.addEventListener("click", () => {
    logout.style.display = 'block';
});
leaveLogOut.addEventListener("click", () => {
    logout.style.display = 'none';
});

document.addEventListener("DOMContentLoaded", () => {
    
    buttonLogOut.addEventListener("click", async () => {

        try {
            const response = await fetch("http://127.0.0.1:8000/logout", {
                method: "POST",
                credentials: "include",
            });

            if (response.ok) {
                window.location.href = "../html/login.html";
            } else {
                return;
            }
        } catch(error) {
            console.error("error: ", error);
        };

    });

});