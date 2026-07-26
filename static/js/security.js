import { fetchWithAuth } from "./api";

let inputCurrentEmail = document.getElementById("currentEmail");
let inputNewEmail = document.getElementById("newEmail");
let inputConfirmNewEmail = document.getElementById("confirmNewEmail");
let inputCurrentPassword = document.getElementById("currentPassword");
let inputPasswordDeleteAccount = document.getElementById("passwordConfirm");
let inputEmailDeleteAccount = document.getElementById("emailConfirm");
let theSameName = document.getElementById("newNameIsTheSame");

let mainEmail = document.getElementById("main-email");
let mainName = document.getElementById("main-name");

let changeName = document.getElementById("change-name");
let changeEmail = document.getElementById("change-email");
let changePassword = document.getElementById("change-password");

let change = document.getElementById("div-change-name-window");
let changeEmailWindow = document.getElementById("div-change-email-window");
let changePasswordWindow = document.getElementById("div-change-password-window");

let leaveChangeName = document.getElementById("leaveChangeName");
let leaveChangeEmail = document.getElementById("leaveChangeEmail");
let leaveChangePassword = document.getElementById("leaveChangePassword");
let leaveDeleteAccount = document.getElementById("leaveDeleteAccount");

let deleteAccountForm = document.getElementById("deleteAccountForm");
let deleteSession = document.getElementById("deleteSession");
let deleteAccount = document.getElementById("deleteAccount");
let incorrectPasswordDeleteAccount = document.getElementById("incorrectPassword");
let incorrectEmailDeleteAccount = document.getElementById("incorrectEmail");
let someErrorDeleteAccount = document.getElementById("someErrorDeleteAccount");


changeName.addEventListener("click", () => {
    change.style.display = "block";
});
changePassword.addEventListener("click", () => {
    changePasswordWindow.style.display = 'block';
});
changeEmail.addEventListener("click", () => {
    changeEmailWindow.style.display = 'block';
});


leaveDeleteAccount.addEventListener("click", () => {
    deleteSession.style.display = 'none';
    inputPasswordDeleteAccount.value = '';
    inputEmailDeleteAccount.value = '';
});
leaveChangeName.addEventListener("click", () => {
    change.style.display = 'none';
});
leaveChangeEmail.addEventListener("click", () => {
    changeEmailWindow.style.display = 'none';
});
leaveChangePassword.addEventListener("click", () => {
    changePasswordWindow.style.display = 'none';
});


deleteAccount.addEventListener("click", () => {
    deleteSession.style.display = 'block';
});


document.addEventListener("DOMContentLoaded", () => {

    let formChangeEmail = document.getElementById("formChangeEmail");
    let formChangeName = document.getElementById("formChangeName");
    let formChangePassword = document.getElementById("formChangePassword");

    let currentNameWrongMessage = document.getElementById("currentNameWrongMessage");

    let differentEmailsMessage = document.getElementById("diferentEmailsMessage");
    let incorrectPasswordMessage = document.getElementById("incorrectPasswordMessage");
    let someErrorEmailMessage = document.getElementById("someError");
    let theSameEmail = document.getElementById("newEmailIsTheSame");
    let currentEmailWrong = document.getElementById("currentEmailWrongMessage");

    let someErrorMessage = document.getElementById("someErrorMessage");

    formChangeName.addEventListener("submit", async (form) => {

        let button = document.getElementById("saveNewName");
        form.preventDefault();

        button.disabled = true;
        const formData = new FormData(e.target);

        try {

            const response = await fetchWithAuth("http://127.0.0.1:8000/change/name", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(Object.fromEntries(formData.entries())),
            })

            if (response.ok) {
                window.location.reload();
            }

        } catch ( error ) {
            console.error("error: ", error)

        } finally {
            button.disabled = false;
        };

    });


    formChangeEmail.addEventListener("submit", async (form) => {

        let button = document.getElementById("saveNewEmail");

        form.preventDefault();
        button.disabled = true;
        const formDataEmail = new FormData(a.target);

        try {
            const response = await fetchWithAuth("http://127.0.0.1:8000/change/email", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                credentials: "include",
                body: JSON.stringify(Object.fromEntries(formDataEmail.entries())),
            });

            if (response.ok) {
                window.location.reload();
            }

        } catch ( error ) {
            console.error("ERROR: ", error)

        } finally {
            button.disabled = false;
        };

    });

    
    deleteAccountForm.addEventListener("submit", async (form) => {
        let button = document.getElementById("buttonDeleteAccount");

        form.preventDefault();

        button.disabled = true;
        const formData = new FormData(form.target);

        try {
            
            const response = await fetchWithAuth("http://127.0.0.1:8000/delete", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(Object.fromEntries(formData.entries())),
            });

            if (response.ok) {
                window.location.href = '../html/login.html'
            }

        } catch (error) {
            console.error("ERROR: ", error);

        } finally {
            button.disabled = false;
        };
        
    });

    formChangePassword.addEventListener("submit", async (form) => {

        let button = document.getElementById("saveNewPassword");
        form.preventDefault();

        button.disabled = true;
        const newFormData = new FormData(form.target);
        
        try {

            const response = await fetchWithAuth("http://127.0.0.1:8000/change/password", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(Object.fromEntries(newFormData.entries())),
            })

            if (response.ok) {
                window.location.reload();
            };

        } catch(error) {
            console.error("error: ", error)
        } finally {
            button.disabled = false;
        }
    })

});