// simple client side behaviours

document.addEventListener("DOMContentLoaded", function () {

  // Show/Hide password toggle.
  // Any <span class="toggle-password" data-target="inputId"> will toggle
  // the type of the input with that id between "password" and "text".
  document.querySelectorAll(".toggle-password").forEach(function (toggle) {
    toggle.addEventListener("click", function () {
      var targetId = toggle.getAttribute("data-target");
      var input = document.getElementById(targetId);
      if (!input) return;

      if (input.type === "password") {
        input.type = "text";
        toggle.textContent = "Hide";
      } else {
        input.type = "password";
        toggle.textContent = "Show";
      }
    });
  });
    
// basic "don't submit empty forms" validation.
// Any <form data-validate> is checked before it is allowed to submit.
  document.querySelectorAll("form[data-validate]").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      var requiredFields = form.querySelectorAll("[required]");
      var errorBox = form.querySelector(".field-error");
      var hasError = false;

      requiredFields.forEach(function (field) {
        if (!field.value.trim()) {
          hasError = true;
        }
      });

      if (hasError) {
        e.preventDefault();
        if (errorBox) {
          errorBox.textContent = "Please fill in all required fields.";
        }
      } else if (errorBox) {
        errorBox.textContent = "";
      }
    });
  });

});
