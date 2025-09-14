from .models import *

def update_order_status(reference, kora_status):
    """
    Map Kora's status to our internal choices and persist.
    """
    try:
        order = Order.objects.get(reference=reference)
    except Order.DoesNotExist:
        return False

    mapping = {
        "success": "paid",
        "pending": "pending",
        "failed":  "failed",
    }
    new_status = mapping.get(kora_status.lower())
    if new_status:
        order.status = new_status
        order.save()
        if hasattr(order, "payment"):
            order.payment.status = (
                "confirmed" if new_status == "paid"
                else new_status
            )
            order.payment.save()
    return True
