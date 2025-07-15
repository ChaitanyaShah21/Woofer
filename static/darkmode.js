document.addEventListener("DOMContentLoaded", function(){
    const toggleButtons = [
        document.getElementById("theme-toggle"),
        document.getElementById("theme-toggle-mobile")
    ];
    const themeIcons = [
        document.getElementById("theme-icon"),
        document.getElementById("theme-icon-mobile")
    ];
    const storedTheme = localStorage.getItem("theme");

        const updateButtonStyle = (theme) => {
        toggleButtons.forEach(btn => {
            if (btn) {
                btn.classList.remove("btn-outline-light", "btn-outline-secondary");
                btn.classList.add(theme === "dark" ? "btn-outline-light" : "btn-outline-secondary");
            }
        });
    };


    const setTheme = (theme) => {
        document.documentElement.setAttribute("data-bs-theme", theme);
        themeIcons.forEach(icon => {
            if (icon) {
                icon.classList.remove("rotate");        
                void icon.offsetWidth;    
                icon.className = theme === "dark" ? "bi bi-sun-fill rotate" : "bi bi-moon-fill rotate";
            }
        });


        updateButtonStyle(theme);
        localStorage.setItem("theme", theme);
    };
    
    if(storedTheme) {
        setTheme(storedTheme);
    }

    toggleButtons.forEach(btn => {
        if(btn) {
            btn.addEventListener("click", () => {
            const currentTheme = document.documentElement.getAttribute("data-bs-theme");
            setTheme(currentTheme === "dark" ? "light" : "dark");
        });
        }
    });
});