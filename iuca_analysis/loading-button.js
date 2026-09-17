ï»¿var setButtonLoading = function (button) {
    const defaultContent = button.querySelector('.button-content-default');
    const loadingContent = button.querySelector('.button-content-loading');

    button.disabled = true;
    defaultContent.classList.add('d-none');
    loadingContent.classList.remove('d-none');
}

var setButtonNormal = function (button) {
    const defaultContent = button.querySelector('.button-content-default');
    const loadingContent = button.querySelector('.button-content-loading');

    button.disabled = false;
    defaultContent.classList.remove('d-none');
    loadingContent.classList.add('d-none');
}