def parse_log(filepath):

    events=[]

    with open(filepath,"r") as f:

        for line in f:

            line=line.strip()

            if not line:

                continue

            parts=line.split()

            if len(parts)<5:

                continue

            event={

                "date":parts[0],

                "time":parts[1],

                "user":parts[2],

                "status":parts[3],

                "ip":parts[4]

            }

            events.append(event)

    return events