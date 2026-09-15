import math
def haversine(lat1, lon1, lat2, lon2):
    R = 6371
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1  
    a = (math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2)
    c = 2 * math.asin(math.sqrt(a))

    return R * c

distance = haversine(28.6, 77.2, 19.0, 72.8)
print(distance)

def check_impossible_travel(distance_km, time_diff_hours):
    if time_diff_hours == 0:
        return True
    speed = distance_km / time_diff_hours
    if speed > 850: 
        return True
    return False

result = check_impossible_travel(1157, 5)
print("Impossible?", result)

def calculate_precision_recall(tp,fp,fn):
    precision = tp/ (tp + fp)
    recall = tp / (tp + fn)
    return precision, recall
p, r = calculate_precision_recall(8, 2, 1)
print("Precision:", p)
print("Recall:", r)