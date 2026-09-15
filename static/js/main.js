document.addEventListener("DOMContentLoaded", () => {
    const logout = document.getElementById("div-log-out-window");
    const logoutButton = document.getElementById("logout-btn");
    const leaveLogOut = document.getElementById("leaveLogOut");
    const buttonLogOut = document.getElementById("buttonLogOut");
    let logoutInProgress = false;

    if (!logout || !logoutButton || !leaveLogOut || !buttonLogOut) {
        return;
    }

    logoutButton.addEventListener("click", () => {
        logout.style.display = 'flex';
    });

    leaveLogOut.addEventListener("click", () => {
        logout.style.display = 'none';
    });

    buttonLogOut.onclick = async () => {
        if (logoutInProgress) {
            return;
        }

        logoutInProgress = true;
        buttonLogOut.disabled = true;

        try {
            const response = await fetch("http://127.0.0.1:8000/logout", {
                method: "POST",
                headers: {
                    "Authorization": "Bearer " + localStorage.getItem("token")
                },
                credentials: "include",
            });

            if (response.ok) {
                window.location.href = "../html/login.html";
                return;
            }

            logout.style.display = 'none';
        } catch (error) {
            console.error("error: ", error);
            logoutInProgress = false;
            buttonLogOut.disabled = false;
        }
    };
});
