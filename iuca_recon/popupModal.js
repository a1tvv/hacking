
var showPopupModal = function (modalType, title, message)
{
    var modal = $('#popupModal');
    modal.removeClass(CONSTS.MODAL_FAIL);
    modal.removeClass(CONSTS.MODAL_SUCCESS);
    modal.addClass(modalType);

    modal.find('.modal-title').html(title);
    modal.find('.modal-body').html(message);
    modal.modal('show');

    // Ensure the modal backdrop appears above other modals
    modal.on('shown.bs.modal', function () {
        // Find the backdrop that was just created for this modal
        $('.modal-backdrop').last().css('z-index', 1055);
    });
}
